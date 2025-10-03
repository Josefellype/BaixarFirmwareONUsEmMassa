package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	COMMAND               = "request firmware onu add tftp://100.76.180.36/DATACOM/V1.5-1020W_250930.tar"
	SOURCE_INVENTORY_FILE = "inventario_olts.json" // Arquivo original do Zabbix
	TARGET_FILE           = "alvos.json"           // Arquivo de trabalho com os alvos
)

// Estruturas para o JSON do Zabbix (sem alterações)
type ZabbixExport struct {
	ZabbixExport struct {
		Hosts []Host `json:"hosts"`
	} `json:"zabbix_export"`
}
type Host struct {
	Hostname   string      `json:"host"`
	Interfaces []Interface `json:"interfaces"`
}
type Interface struct {
	Type string `json:"type"`
	IP   string `json:"ip"`
}

// --- ESTRUTURA MODIFICADA ---
// OLT agora tem tags JSON para que possamos ler e escrever o alvos.json
type OLT struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// extractOLTs do inventário Zabbix (sem alterações)
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

// executeSSHCommand (sem alterações)
func executeSSHCommand(olt OLT, username, password string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	var result strings.Builder
	result.WriteString("----------------------------------------\n")
	result.WriteString(fmt.Sprintf("Hostname: %s\n", olt.Hostname))
	result.WriteString(fmt.Sprintf("IP: %s\n", olt.IP))

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", olt.IP+":22", config)
	if err != nil {
		result.WriteString("Status: ❌ Falha na conexão\n")
		result.WriteString(fmt.Sprintf("Erro: %v\n", err))
		results <- result.String()
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		result.WriteString("Status: ❌ Falha ao criar sessão\n")
		result.WriteString(fmt.Sprintf("Erro: %v\n", err))
		results <- result.String()
		return
	}
	defer session.Close()

	output, err := session.CombinedOutput(COMMAND)
	if err != nil {
		result.WriteString("Status: ❌ Falha na execução do comando\n")
		result.WriteString(fmt.Sprintf("Erro: %v\n", err))
	} else {
		// Analisa a saída para um status mais preciso
		if strings.Contains(string(output), "Error:") {
			result.WriteString("Status: ⚠️ Comando executado, mas retornou erro\n")
		} else {
			result.WriteString("Status: ✅ Comando executado com sucesso\n")
		}
	}

	result.WriteString("Saída do Comando:\n")
	result.WriteString(string(output))
	result.WriteString("\n----------------------------------------")

	results <- result.String()
}

func main() {
	var olts []OLT

	// --- NOVA LÓGICA DE ARQUIVOS ---
	// Verifica se o arquivo de alvos existe
	_, err := os.Stat(TARGET_FILE)
	if os.IsNotExist(err) {
		fmt.Printf("Arquivo '%s' não encontrado. Gerando a partir de '%s'...\n", TARGET_FILE, SOURCE_INVENTORY_FILE)

		// Lê o arquivo fonte original
		sourceData, err := ioutil.ReadFile(SOURCE_INVENTORY_FILE)
		if err != nil {
			log.Fatalf("Falha ao ler o arquivo de inventário fonte '%s': %v", SOURCE_INVENTORY_FILE, err)
		}

		// Extrai as OLTs
		olts, err = extractOLTs(sourceData)
		if err != nil {
			log.Fatalf("Falha ao extrair dados do inventário: %v", err)
		}

		// Converte a lista de OLTs para um JSON formatado
		targetData, err := json.MarshalIndent(olts, "", "  ") // "  " para indentação
		if err != nil {
			log.Fatalf("Falha ao formatar JSON para o arquivo de alvos: %v", err)
		}

		// Escreve o novo arquivo de alvos
		err = ioutil.WriteFile(TARGET_FILE, targetData, 0644)
		if err != nil {
			log.Fatalf("Falha ao escrever o arquivo de alvos '%s': %v", TARGET_FILE, err)
		}
		fmt.Printf("Arquivo '%s' criado com sucesso. O script continuará a execução com todos os %d alvos.\n", TARGET_FILE, len(olts))

	} else {
		// Se o arquivo já existe, lê dele
		fmt.Printf("Usando lista de alvos do arquivo existente '%s'.\n", TARGET_FILE)
		targetData, err := ioutil.ReadFile(TARGET_FILE)
		if err != nil {
			log.Fatalf("Falha ao ler o arquivo de alvos '%s': %v", TARGET_FILE, err)
		}

		// Decodifica o JSON do arquivo de alvos para a lista de OLTs
		if err := json.Unmarshal(targetData, &olts); err != nil {
			log.Fatalf("Falha ao decodificar o JSON do arquivo de alvos: %v", err)
		}
	}
	// --- FIM DA NOVA LÓGICA ---

	if len(olts) == 0 {
		log.Println("Nenhum alvo para processar. Verifique seu arquivo 'alvos.json'.")
		return
	}

	// Coleta de credenciais (sem alteração)
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

	fmt.Printf("Iniciando execução em %d OLTs...\n\n", len(olts))

	// Execução concorrente (sem alteração)
	var wg sync.WaitGroup
	results := make(chan string, len(olts))
	for _, olt := range olts {
		wg.Add(1)
		go executeSSHCommand(olt, username, password, &wg, results)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Println("=== INÍCIO DOS RESULTADOS ===")
	for res := range results {
		fmt.Printf("%s\n\n", res)
	}
	fmt.Println("=== FIM DOS RESULTADOS ===")
	fmt.Println("\nProcesso concluído.")
}
