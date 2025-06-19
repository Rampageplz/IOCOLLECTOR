# IOC Collector

Este projeto realiza a coleta diária de indicadores de comprometimento (IOCs) de diferentes feeds de Threat Intelligence. Os coletores incluem [AbuseIPDB](https://www.abuseipdb.com/), [AlienVault OTX](https://otx.alienvault.com/), [URLHaus](https://urlhaus.abuse.ch/) e integrações extras como ThreatFox, MISP, Shodan, Censys, VirusTotal, GreyNoise, Hybrid Analysis, Google Safe Browsing e feeds adicionais do abuse.ch.

## Estrutura

- `ioc_collector/collectors/collector_abuse.py` - funções para a API do AbuseIPDB
- `ioc_collector/collectors/collector_otx.py` - coletor do AlienVault OTX
- `ioc_collector/collectors/collector_urlhaus.py` - coletor do URLHaus
- `ioc_collector/collectors/collector_threatfox.py` - ThreatFox
- `ioc_collector/collectors/collector_misp.py` - MISP
- `ioc_collector/collectors/collector_shodan.py` - Shodan
- `ioc_collector/collectors/collector_censys.py` - Censys
- `ioc_collector/collectors/collector_virustotal.py` - VirusTotal
- `ioc_collector/collectors/collector_greynoise.py` - GreyNoise
- `ioc_collector/collectors/collector_hybridanalysis.py` - Hybrid Analysis
- `ioc_collector/collectors/collector_gsb.py` - Google Safe Browsing
- `ioc_collector/collectors/collector_ransomware.py` - Feed de ransomware
- `ioc_collector/collectors/collector_malspam.py` - Feed de malspam
**Observação:** os coletores ThreatFox, MISP, Shodan, Censys, VirusTotal, GreyNoise, Hybrid Analysis e Google Safe Browsing são implementações simplificadas apenas como _placeholders_. Eles ilustram a integração com essas APIs, mas podem exigir ajustes e chaves válidas. Os demais coletores continuam funcionais.

- `ioc_collector/alerts_manager.py` - gerencia o arquivo `alerts.json`
- `ioc_collector/utils/utils.py` - utilidades diversas
- `ioc_collector/main.py` - ponto de entrada da aplicação
- `ioc.db` - banco SQLite com todos os IOCs coletados (evita duplicados)
- `data/{source}/` - arquivos diários de cada feed
- `logs/` - arquivos de log nos formatos `YYYY-MM-DD.log` e `YYYY-MM-DD.json`
- cada IOC inclui o campo `time` com data e hora em UTC no formato
  `YYYY-MM-DDTHH:MM:SSZ`

## Uso

1. Crie e ative um ambiente virtual (opcional, mas recomendado):

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

2. Instale as dependências:

   ```bash
   pip install -r ioc_collector/requirements.txt
   ```

3. Defina as API keys no arquivo `config.json` na seção `API_KEYS` ou nas
   variáveis de ambiente correspondentes (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`,
   `URLHAUS_API_KEY`). Caso o `config.json` não exista ele será criado com um
   template básico na primeira execução.

   ```bash
 ABUSEIPDB_API_KEY=SUACHAVE
  OTX_API_KEY=CHAVE_OTX  # opcional
  ```

   Defina também `ACTIVE_COLLECTORS` se quiser habilitar ou desabilitar feeds.
   Para testes offline do AbuseIPDB utilize `ABUSE_MOCK_FILE` com um JSON de
   amostra (ex.: `data/mock/abuse_sample.json`). Quando esse arquivo é definido
   a chave do AbuseIPDB torna-se opcional.

### Testes com API real ou mock

Para usar as APIs reais, apenas garanta que as chaves estejam presentes no `.env`.
Se `ABUSE_MOCK_FILE` estiver definido, o coletor do AbuseIPDB usará o arquivo
informado em vez da API, útil quando o limite de requisições é atingido.

O OTX possui limite diário de requisições (documentação indica cerca de 1000
chamadas/dia). Ao ultrapassar esse valor o serviço retorna HTTP 429.

4. Execute o coletor:

   ```bash
   python -m ioc_collector.main
   ```

   Após a coleta um relatório consolidado é salvo automaticamente nos arquivos
   `ioc_correlation_report.csv` e `ioc_correlation_report.xlsx` contendo a
  correlação dos IOCs entre os feeds. O arquivo Excel organiza os indicadores
  em abas separadas (`IPs`, `URLs`, `Hashes` e `Domínios`) com informações
  adicionais de país, ASN, data de publicação e pontuações de risco.

5. Para exibir os IPs mais reportados em determinada data:

   ```bash
   python -m ioc_collector.main --top AAAA-MM-DD
   ```

É possível definir o nível de log e escolher os coletores em tempo de execução:

```bash
python -m ioc_collector.main --log-level DEBUG --collectors abuseipdb,otx
```

### Configuração

O arquivo `config.json` define parâmetros dos coletores. Exemplo:

```json
{
  "CONFIDENCE_MINIMUM": 80,
  "LIMIT_DETAILS": 100,
  "MAX_AGE_IN_DAYS": 1,
  "ACTIVE_COLLECTORS": "abuseipdb,otx,urlhaus",
  "GENERATE_REQUIREMENTS": true,
  "API_KEYS": {
    "ABUSEIPDB": "",
    "OTX": "",
    "URLHAUS": ""
  }
}
```

`CONFIDENCE_MINIMUM`, `LIMIT_DETAILS` e `MAX_AGE_IN_DAYS` são usados pelo coletor do AbuseIPDB. `ACTIVE_COLLECTORS` define quais feeds estarão habilitados (separados por vírgula). `API_KEYS` centraliza todas as chaves necessárias para os coletores. `GENERATE_REQUIREMENTS` controla a criação automática do `requirements.txt`.
Para testes locais sem acessar a API, informe `ABUSE_MOCK_FILE` apontando para um JSON com o retorno esperado.

## Debug

Os logs sao gravados em `logs/` e tambem exibidos coloridos no terminal utilizando `rich`. Para aumentar a verbosidade, altere o nivel em `setup_logging()` para `DEBUG`.

## Relatórios e correlação

Após cada execução do coletor principal é gerado automaticamente um relatório
com a correlação dos IOCs encontrados nas diferentes fontes. Para consultas
manuais ou filtros adicionais continue utilizando o módulo `ioc_collector.report`:

```bash
python -m ioc_collector.report --date AAAA-MM-DD --output-json relatorio.json
```

Também é possível gerar arquivos em CSV, TXT, Excel ou PDF:

```bash
python -m ioc_collector.report --date AAAA-MM-DD --output-csv relatorio.csv \
    --output-txt relatorio.txt \
    --output-xls relatorio.xls \
    --output-xlsx relatorio.xlsx \
    --output-pdf relatorio.pdf
```

Para visualizar apenas IOCs duplicados utilize:

```bash
python -m ioc_collector.report --date AAAA-MM-DD --only-duplicates
```

Ou apenas o ranking de recorrências:

```bash
python -m ioc_collector.report --date AAAA-MM-DD --only-top
```

Use os filtros `--type`, `--source` e `--value` para limitar a consulta. O
parâmetro `--top-count` define quantos IOCs devem aparecer na seção "Top". Utilize
`--sort` para ordenar a lista completa por data/hora. Os flags `--only-duplicates`
e `--only-top` controlam quais seções são exibidas. Caso não haja registros para a
data informada será exibido `⚠️ Nenhum IOC encontrado para a data X`.
