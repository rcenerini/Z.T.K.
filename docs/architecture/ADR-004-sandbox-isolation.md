# ADR-004: Escolha de Runtime Isolado para Sandbox de PoC

| Campo | Valor |
|-------|-------|
| **Status** | Proposto |
| **Data** | 2026-07-27 |
| **Autor** | ZTK Strategist Agent |
| **Stakeholders** | Arquitetura, Segurança, Infraestrutura |

---

## Contexto

A Camada 3 (Validação) executa Provas de Conceito (PoC) para confirmar se uma vulnerabilidade é explorável. Essas PoCs envolvem executar código potencialmente malicioso (exploits, payloads) em ambiente controlado. O sandbox deve garantir:

1. **Isolamento total**: código malicioso não pode escapar para o host ou rede
2. **Sem acesso a dados reais**: PoC nunca toca PAN, PII, ou credenciais
3. **Descarte após uso**: ambiente é destruído após cada PoC
4. **Custo viável**: centenas de PoCs por dia não podem custar uma fortuna

## Decisão

Usaremos **AWS Firecracker** (via Lambda ou EC2 bare-metal) como runtime de sandbox.

### Por que Firecracker

- **MicroVM**: cada PoC roda em sua própria microVM com kernel mínimo (5-10MB)
- **Tempo de boot <125ms**: comparável a containers, muito mais rápido que VMs tradicionais
- **Isolamento de hardware**: KVM-based, mesmo nível de isolamento que EC2
- **Sem rede por padrão**: network stack é opcional e configurável
- **Sem filesystem do host**: rootfs é efêmero, destruído após execução
- **Integração nativa AWS**: Lambda usa Firecracker internamente, EC2 bare-metal suporta
- **Custo**: ~$0.0001 por PoC (EC2 i3.metal com 100+ microVMs simultâneas)

### Configuração do Sandbox

```yaml
sandbox_config:
  runtime: firecracker
  vcpu: 1
  memory_mb: 256
  disk_mb: 512
  network: none                # Sem acesso à rede
  host_fs: none                # Sem acesso ao filesystem do host
  timeout_seconds: 30          # Hard timeout
  seccomp_profile: strict      # syscalls mínimos
  readonly_rootfs: true
  tmpfs_size_mb: 64            # Para arquivos temporários do exploit
```

### Pipeline de Execução

```
1. Provisionar microVM Firecracker (boot <125ms)
2. Copiar código alvo + payload para tmpfs
3. Executar com timeout de 30s
4. Capturar stdout, stderr, exit code
5. Destruir microVM
6. Retornar resultado (exploitável / não-exploitável / inconclusivo)
```

### O que NÃO usamos

- **NÃO usamos Docker/gVisor** — isolamento de container é mais fraco que KVM
- **NÃO usamos Kata Containers** — sobrecarga maior, boot mais lento
- **NÃO reutilizamos microVMs** — cada PoC tem ambiente limpo

## Consequências

### Positivas
- Isolamento forte (KVM) — mesmo nível que EC2
- Boot rápido — não impacta latência do pipeline
- Sem risco de vazamento entre PoCs (ambiente descartável)
- Integração AWS nativa (sem dependência externa)

### Negativas
- Requer EC2 bare-metal (i3.metal, m5.metal) — custo fixo mais alto
- Overhead de gerenciamento de pool de microVMs
- Debug mais difícil (ambiente é destruído após execução)

### Riscos Residuais
- **Escape de KVM**: vulnerabilidade no KVM/hypervisor
  - Mitigação: EC2 bare-metal com kernel atualizado, AWS Nitro Security
- **Exfiltração via timing**: exploit usa side-channel de tempo
  - Mitigação: sem rede, sem shared resources entre microVMs

## Alternativas Consideradas

| Alternativa | Isolamento | Boot | Custo | Decisão |
|-------------|-----------|------|-------|---------|
| Docker | Fraco (kernel compartilhado) | <1s | Baixo | Rejeitado |
| gVisor | Médio (syscall interception) | <1s | Baixo | Rejeitado |
| Kata Containers | Forte (VM leve) | 1-2s | Médio | Rejeitado |
| **Firecracker** | **Forte (KVM)** | **<125ms** | **Médio** | **Selecionado** |
| EC2 dedicada por PoC | Máximo | 30-60s | Alto | Rejeitado |

## Validação

- [ ] 100 PoCs simultâneas sem interferência entre microVMs
- [ ] Tentativa de escape documentada e bloqueada (network, fs, syscalls)
- [ ] Latência total <5s (provisionar + executar + destruir)
- [ ] Custo <$0.001 por PoC em escala
- [ ] Teste de penetração: 5 técnicas de escape conhecidas, todas bloqueadas
