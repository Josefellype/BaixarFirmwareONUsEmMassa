package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Constantes
const (
	DOWNLOAD_COMMAND      = "request firmware onu add tftp://100.76.180.36/DATACOM/US_HG7_HG9_v2.0.13_300002167_en_xpon.tar"
	SHOW_FIRMWARE_COMMAND = "show firmware onu"
	SOURCE_INVENTORY_FILE = "inventario_olts.json"
	TARGET_FILE           = "alvos.json"
)

// Estruturas de Dados
type OLT struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}
type OLTResult struct {
	OLT     OLT
	Output  string
	Success bool
}
type FirmwareInfo struct {
	Name, MD5, Size string
}

type Host struct {
	Hostname   string      `json:"host"`
	Interfaces []Interface `json:"interfaces"`
}
type Interface struct {
	Type string `json:"type"`
	IP   string `json:"ip"`
}

// Estruturas para o JSON do Zabbix (sem alterações)
type ZabbixExport struct {
	ZabbixExport struct {
		Hosts []Host `json:"hosts"`
	} `json:"zabbix_export"`
}

func extractOLTs(data []byte) ([]OLT, error) {
	var zabbixData ZabbixExport
	if err := json.Unmarshal(data, &zabbixData); err != nil {
		return nil, fmt.Errorf("erro ao decodificar JSON do Zabbix: %w", err)
	}
	var olts []OLT
	for _, host := range zabbixData.ZabbixExport.Hosts {
		for _, iface := range host.Interfaces {
			if iface.Type == "SNMP" {
				olts = append(olts, OLT{Hostname: host.Hostname, IP: iface.IP})
				break
			}
		}
	}
	return olts, nil
}

// sshExecute (sem alterações)
func sshExecute(olt OLT, username, password, command string) (string, error) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}
	client, err := ssh.Dial("tcp", olt.IP+":22", config)
	if err != nil {
		return "", fmt.Errorf("falha ao conectar: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("falha ao criar sessão: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("falha ao executar comando: %w", err)
	}
	return string(output), nil
}

// concurrentInitialDownload (wrapper para a primeira fase)
func concurrentInitialDownload(olt OLT, username, password string, wg *sync.WaitGroup, results chan<- OLTResult) {
	defer wg.Done()
	output, err := sshExecute(olt, username, password, DOWNLOAD_COMMAND)
	success := err == nil && !strings.Contains(output, "Error: ONU firmware file download has failed")
	results <- OLTResult{OLT: olt, Output: output, Success: success}
}

// parseShowFirmwareOutput (sem alterações)
func parseShowFirmwareOutput(output string) []FirmwareInfo {
	re := regexp.MustCompile(`Name\s*:\s*(?P<name>.*?)\s*\n\s*MD5\s*:\s*(?P<md5>.*?)\s*\n\s*Size\s*:\s*(?P<size>.*)`)
	matches := re.FindAllStringSubmatch(output, -1)
	var firmwares []FirmwareInfo
	for _, match := range matches {
		fw := FirmwareInfo{}
		for i, name := range re.SubexpNames() {
			if i > 0 && i <= len(match) {
				switch name {
				case "name":
					fw.Name = strings.TrimSpace(match[i])
				case "md5":
					fw.MD5 = strings.TrimSpace(match[i])
				case "size":
					fw.Size = strings.TrimSpace(match[i])
				}
			}
		}
		firmwares = append(firmwares, fw)
	}
	return firmwares
}

// remediationWorker é a tarefa que executa em background para uma OLT
func remediationWorker(olt OLT, username, password string, firmwaresToRemove []string, wg *sync.WaitGroup, results chan<- OLTResult) {
	defer wg.Done()

	// 1. Remover firmwares
	for _, fwName := range firmwaresToRemove {
		fmt.Printf("  -> [BG] Removendo '%s' em %s...\n", fwName, olt.Hostname)
		removeCmd := fmt.Sprintf("request firmware onu remove %s", fwName)
		// Ignoramos a saída da remoção por enquanto, focando no resultado do download
		sshExecute(olt, username, password, removeCmd)
	}

	// 2. Tentar download novamente
	fmt.Printf("  -> [BG] Iniciando novo download em %s...\n", olt.Hostname)
	output, err := sshExecute(olt, username, password, DOWNLOAD_COMMAND)
	success := err == nil && !strings.Contains(output, "Error:")

	results <- OLTResult{OLT: olt, Output: output, Success: success}
}

// formatResult cria o bloco de texto formatado para a saída de um resultado.
func formatResult(result OLTResult) string {
	var sb strings.Builder
	sb.WriteString("----------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Hostname: %s\n", result.OLT.Hostname))
	sb.WriteString(fmt.Sprintf("IP: %s\n", result.OLT.IP))

	if result.Success {
		sb.WriteString("Status: ✅ Download inicial bem-sucedido\n")
	} else {
		sb.WriteString("Status: ❌ Download inicial falhou\n")
	}

	sb.WriteString("Saída do Comando:\n")
	sb.WriteString(strings.TrimSpace(result.Output))
	sb.WriteString("\n----------------------------------------\n")
	return sb.String()
}

func main() {
	// --- Lógica de Carregamento do `alvos.json` (sem alterações) ---
	var olts []OLT
	_, err := os.Stat(TARGET_FILE)
	if os.IsNotExist(err) {
		fmt.Printf("Arquivo '%s' não encontrado. Gerando a partir de '%s'...\n", TARGET_FILE, SOURCE_INVENTORY_FILE)
		sourceData, err := ioutil.ReadFile(SOURCE_INVENTORY_FILE)
		if err != nil {
			log.Fatalf("Falha ao ler o arquivo de inventário fonte '%s': %v", SOURCE_INVENTORY_FILE, err)
		}
		olts, err = extractOLTs(sourceData)
		if err != nil {
			log.Fatalf("Falha ao extrair dados do inventário: %v", err)
		}
		targetData, err := json.MarshalIndent(olts, "", "  ")
		if err != nil {
			log.Fatalf("Falha ao formatar JSON para o arquivo de alvos: %v", err)
		}
		err = ioutil.WriteFile(TARGET_FILE, targetData, 0644)
		if err != nil {
			log.Fatalf("Falha ao escrever o arquivo de alvos '%s': %v", TARGET_FILE, err)
		}
		fmt.Printf("Arquivo '%s' criado. O script continuará com %d alvos.\n", TARGET_FILE, len(olts))
	} else {
		fmt.Printf("Usando lista de alvos do arquivo existente '%s'.\n", TARGET_FILE)
		targetData, err := ioutil.ReadFile(TARGET_FILE)
		if err != nil {
			log.Fatalf("Falha ao ler o arquivo de alvos '%s': %v", TARGET_FILE, err)
		}
		if err := json.Unmarshal(targetData, &olts); err != nil {
			log.Fatalf("Falha ao decodificar o JSON do arquivo de alvos: %v", err)
		}
	}
	if len(olts) == 0 {
		log.Println("Nenhum alvo para processar.")
		return
	}

	// --- Coleta de Credenciais (sem alterações) ---
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Usuário SSH: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	fmt.Print("Senha SSH: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Falha ao ler a senha: %v", err)
	}
	password := string(bytePassword)
	fmt.Println()

	// --- FASE 1: Execução em Massa Inicial ---
	fmt.Printf("\n--- FASE 1: Iniciando download em massa em %d OLTs... ---\n", len(olts))
	var initialWg sync.WaitGroup
	initialResultsChan := make(chan OLTResult, len(olts))

	// Slice para armazenar os resultados para análise posterior
	initialResults := make([]OLTResult, 0, len(olts))

	// Goroutine para processar e imprimir os resultados da Fase 1 em tempo real
	var processingWg sync.WaitGroup
	processingWg.Add(1)
	go func() {
		defer processingWg.Done()
		for result := range initialResultsChan {
			fmt.Print(formatResult(result))                 // Exibe o resultado formatado assim que chega
			initialResults = append(initialResults, result) // Guarda o resultado para a próxima fase
		}
	}()

	// Dispara os workers para fazer o download
	for _, olt := range olts {
		initialWg.Add(1)
		go concurrentInitialDownload(olt, username, password, &initialWg, initialResultsChan)
	}

	initialWg.Wait()          // Espera todos os downloads terminarem
	close(initialResultsChan) // Fecha o canal para sinalizar à goroutine de processamento que não há mais resultados
	processingWg.Wait()       // Espera a goroutine de processamento/impressão terminar

	// --- Análise Pós-Fase 1 ---
	var failedOLTs []OLT
	var successfulCount int

	// Agora, analisamos os resultados que foram coletados
	for _, result := range initialResults {
		if result.Success {
			successfulCount++
		} else {
			failedOLTs = append(failedOLTs, result.OLT)
		}
	}
	fmt.Printf("\n--- Resumo da Fase 1: %d OLTs com sucesso, %d OLTs com falha no download. ---\n", successfulCount, len(failedOLTs))

	// --- FASE 3: Pipeline de Remediação (se houver falhas) ---
	remediationRound := 1
	for len(failedOLTs) > 0 {
		fmt.Printf("\n--- INICIANDO RODADA DE REMEDIAÇÃO #%d PARA %d OLTs ---\n", remediationRound, len(failedOLTs))

		var remediationWg sync.WaitGroup
		remediationResultsChan := make(chan OLTResult, len(failedOLTs))

		// a. Avisará sobre a falha e a quantidade.
		fmt.Printf("A causa provável da falha é falta de espaço. Vamos inspecionar cada OLT.\n")

		// Loop de Coleta de Input (sequencial e interativo)
		for i, olt := range failedOLTs {
			fmt.Printf("\n--- Coletando Ação para OLT %d/%d: %s (%s) ---\n", i+1, len(failedOLTs), olt.Hostname, olt.IP)

			fmt.Println("Buscando lista de firmwares...")
			output, err := sshExecute(olt, username, password, SHOW_FIRMWARE_COMMAND)
			if err != nil {
				fmt.Printf("ERRO: Não foi possível buscar firmwares: %v. Esta OLT será pulada nesta rodada.\n", err)
				continue
			}

			firmwares := parseShowFirmwareOutput(output)
			var firmwaresToRemove []string

			if len(firmwares) > 0 {
				fmt.Println("Firmwares encontrados:")
				for j, fw := range firmwares {
					fmt.Printf("  [%d] %s (Tamanho: %s)\n", j+1, fw.Name, fw.Size)
				}

				fmt.Print("\n> Digite os NÚMEROS dos firmwares a remover (ex: 1,3) ou pressione ENTER para pular: ")
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)

				if input != "" {
					indicesStr := strings.Split(input, ",")
					for _, idxStr := range indicesStr {
						idx, err := strconv.Atoi(strings.TrimSpace(idxStr))
						if err == nil && idx >= 1 && idx <= len(firmwares) {
							firmwaresToRemove = append(firmwaresToRemove, firmwares[idx-1].Name)
						}
					}
				}
			} else {
				fmt.Println("Nenhum firmware encontrado para remover.")
			}

			// h. Inicia o download em background e passa para a próxima OLT
			fmt.Printf("Ação definida para %s. Iniciando tarefa em background...\n", olt.Hostname)
			remediationWg.Add(1)
			go remediationWorker(olt, username, password, firmwaresToRemove, &remediationWg, remediationResultsChan)
		}

		// i. Exibe mensagem para aguardar
		fmt.Printf("\n>> Todas as ações foram coletadas. Aguardando a finalização das %d tarefas em background...\n\n", len(failedOLTs))
		remediationWg.Wait()
		close(remediationResultsChan)

		// j. Verifica se o download falhou novamente
		var nextWaveFailures []OLT
		fmt.Println("--- Resultados da Rodada de Remediação ---")
		for result := range remediationResultsChan {
			if result.Success {
				fmt.Printf("[ SUCESSO ] %s (%s)\n", result.OLT.Hostname, result.OLT.IP)
			} else {
				fmt.Printf("[  FALHA  ] %s (%s) - Motivo: %s\n", result.OLT.Hostname, result.OLT.IP, strings.TrimSpace(result.Output))
				nextWaveFailures = append(nextWaveFailures, result.OLT)
			}
		}

		failedOLTs = nextWaveFailures // Prepara para a próxima iteração do loop
		remediationRound++
	}

	fmt.Println("\nProcesso concluído.")
}
