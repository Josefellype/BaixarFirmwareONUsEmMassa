package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
	DOWNLOAD_COMMAND      = "request firmware onu add tftp://100.76.180.36/DATACOM/1216-17-DM986-100-SFU.tar"
	SHOW_FIRMWARE_COMMAND = "show firmware onu"
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

// --- ESTRUTURAS PARA A API ZABBIX ---

// ZabbixRequest é a estrutura genérica para todos os pedidos JSON-RPC
type ZabbixRequest struct {
	Jsonrpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	Auth    string      `json:"auth,omitempty"` // omitempty faz com que o campo seja omitido se estiver vazio
	ID      int         `json:"id"`
}

// ZabbixResponse é a estrutura genérica para as respostas
type ZabbixResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

// HostInterface define a estrutura da interface de um host
type HostInterface struct {
	IP string `json:"ip"`
}

// Host define a estrutura de um host retornado pela API
type Host struct {
	HostID     string          `json:"hostid"`
	Hostname   string          `json:"host"`
	Interfaces []HostInterface `json:"interfaces"`
}

// --- CLIENTE DA API ZABBIX ---

const (
	ZABBIX_API_URL = "http://100.76.180.210/api_jsonrpc.php"
	ZABBIX_USER    = "arcpath_api"
	ZABBIX_PASS    = "k4p9nort3"
	TEMPLATE_NAME  = "Provedor - Datacom OLT"
)

// zabbixRequest é nossa função "garçom" genérica.
func zabbixRequest(payload ZabbixRequest) (interface{}, error) {
	// Serializa o nosso struct Go para JSON (equivalente ao json.dumps() do Python)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("erro ao serializar payload: %w", err)
	}

	// Cria a requisição HTTP POST (equivalente ao requests.post() do Python)
	req, err := http.NewRequest("POST", ZABBIX_API_URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("erro ao criar requisição: %w", err)
	}
	req.Header.Set("Content-Type", "application/json-rpc")

	// Envia a requisição
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro ao enviar requisição para a API Zabbix: %w", err)
	}
	defer resp.Body.Close()

	// Lê o corpo da resposta
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta da API: %w", err)
	}

	// Desserializa a resposta JSON para nosso struct (equivalente ao r.json() do Python)
	var zabbixResp ZabbixResponse
	if err := json.Unmarshal(body, &zabbixResp); err != nil {
		return nil, fmt.Errorf("erro ao desserializar resposta da API: %w", err)
	}

	// Verifica por erros lógicos da API Zabbix
	if zabbixResp.Error.Code != 0 {
		return nil, fmt.Errorf("erro da API Zabbix: %s - %s", zabbixResp.Error.Message, zabbixResp.Error.Data)
	}

	return zabbixResp.Result, nil
}

// ZabbixLogin autentica e retorna um token
func ZabbixLogin() (string, error) {
	payload := ZabbixRequest{
		Jsonrpc: "2.0",
		Method:  "user.login",
		Params:  map[string]string{"username": ZABBIX_USER, "password": ZABBIX_PASS},
		ID:      1,
	}

	result, err := zabbixRequest(payload)
	if err != nil {
		return "", err
	}
	// O resultado é uma string, então fazemos um "type assertion"
	authToken, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("token de autenticação inválido")
	}
	return authToken, nil
}

// GetTemplateID busca o ID de um template pelo nome, tentando tanto pelo 'host' quanto pelo 'name'.
func GetTemplateID(auth string) (string, error) {
	// --- PRIMEIRA TENTATIVA: Buscar pelo campo 'host' (nome técnico) ---
	payload := ZabbixRequest{
		Jsonrpc: "2.0",
		Method:  "template.get",
		Params:  map[string]interface{}{"output": "templateid", "filter": map[string][]string{"host": {TEMPLATE_NAME}}},
		Auth:    auth,
		ID:      1,
	}
	result, err := zabbixRequest(payload)
	if err != nil {
		return "", err
	}

	templates := result.([]interface{})

	// --- SE A PRIMEIRA TENTATIVA FALHAR, TENTA PELO CAMPO 'name' (nome visível) ---
	if len(templates) == 0 {
		fmt.Println("Template não encontrado pelo 'host', tentando pelo 'name'...")
		payload.Params = map[string]interface{}{"output": "templateid", "filter": map[string][]string{"name": {TEMPLATE_NAME}}}
		result, err = zabbixRequest(payload)
		if err != nil {
			return "", err
		}
		templates = result.([]interface{})
	}

	// Se ainda assim não encontrar, retorna o erro
	if len(templates) == 0 {
		return "", fmt.Errorf("template '%s' não encontrado nem por 'host' nem por 'name'", TEMPLATE_NAME)
	}

	// Extrai o ID do primeiro resultado encontrado
	templateID := templates[0].(map[string]interface{})["templateid"].(string)
	return templateID, nil
}

// GetHostsByTemplate busca todas as OLTs e as converte para nosso formato interno
func GetHostsByTemplate(auth, templateID string) ([]OLT, error) {
	payload := ZabbixRequest{
		Jsonrpc: "2.0",
		Method:  "host.get",
		Params:  map[string]interface{}{"output": []string{"hostid", "host"}, "templateids": templateID, "selectInterfaces": "extend"},
		Auth:    auth,
		ID:      1,
	}
	result, err := zabbixRequest(payload)
	if err != nil {
		return nil, err
	}
	//fmt.Println("Hosts encontrados:", result)

	// Precisamos converter o resultado genérico para nossa struct Host
	resultBytes, _ := json.Marshal(result)
	var hosts []Host
	if err := json.Unmarshal(resultBytes, &hosts); err != nil {
		return nil, fmt.Errorf("erro ao converter hosts: %w", err)
	}

	// Converte a lista de Hosts da API para a lista de OLTs que o resto do nosso script usa
	var olts []OLT
	for _, host := range hosts {
		if len(host.Interfaces) > 0 {
			olts = append(olts, OLT{Hostname: host.Hostname, IP: host.Interfaces[0].IP})
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
	fmt.Println("--- FASE 0: Buscando lista de OLTs na API do Zabbix ---")

	// 1. Autenticar na API
	fmt.Println("Autenticando na API Zabbix...")
	authToken, err := ZabbixLogin()
	if err != nil {
		log.Fatalf("ERRO FATAL: Falha no login da API Zabbix: %v", err)
	}
	fmt.Println("Login bem-sucedido.")

	// 2. Obter o ID do Template
	fmt.Println("Buscando ID do template...")
	templateID, err := GetTemplateID(authToken)
	if err != nil {
		log.Fatalf("ERRO FATAL: Falha ao buscar template ID: %v", err)
	}
	fmt.Printf("Template ID encontrado: %s\n", templateID)

	// 3. Obter a lista de hosts (OLTs)
	fmt.Println("Buscando hosts do template...")
	olts, err := GetHostsByTemplate(authToken, templateID)
	if err != nil {
		log.Fatalf("ERRO FATAL: Falha ao buscar hosts: %v", err)
	}
	fmt.Printf("%d OLTs encontradas na API.\n", len(olts))

	if len(olts) == 0 {
		log.Println("Nenhum alvo encontrado na API. Encerrando.")
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
