# IOC Collector

Este projeto realiza a coleta diária de indicadores de comprometimento (IOCs) de diferentes feeds de Threat Intelligence. Atualmente são suportados [AbuseIPDB](https://www.abuseipdb.com/), [AlienVault OTX](https://otx.alienvault.com/) e [URLHaus](https://urlhaus.abuse.ch/).

## Estrutura

- `ioc_collector/collectors/collector_abuse.py` - funções para a API do AbuseIPDB
- `ioc_collector/collectors/collector_otx.py` - coletor do AlienVault OTX
- `ioc_collector/collectors/collector_urlhaus.py` - coletor do URLHaus
- `ioc_collector/alerts_manager.py` - gerencia o arquivo `alerts.json`
- `ioc_collector/utils/utils.py` - utilidades diversas
- `ioc_collector/main.py` - ponto de entrada da aplicação
- `data/{source}/` - arquivos diários de cada feed
- `logs/` - arquivos de log nos formatos `YYYY-MM-DD.log` e `YYYY-MM-DD.json`

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

3. Crie um arquivo `.env` dentro da pasta `ioc_collector/` com as chaves de API
   necessárias:

   ```bash
 ABUSEIPDB_API_KEY=SUACHAVE
  OTX_API_KEY=CHAVE_OTX  # opcional
  ```

   Defina também `ACTIVE_COLLECTORS` caso queira habilitar ou desabilitar feeds.
   Para testes offline do AbuseIPDB defina `ABUSE_MOCK_FILE` apontando para um
   arquivo JSON contendo os dados simulados do feed (ex.: `data/mock/abuse_sample.json`).

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

5. Para exibir os IPs mais reportados em determinada data:

   ```bash
   python -m ioc_collector.main --top AAAA-MM-DD
   ```

### Configuração

O arquivo `config.json` define parâmetros dos coletores. Exemplo:

```json
{
  "CONFIDENCE_MINIMUM": 80,
  "LIMIT_DETAILS": 100,
  "MAX_AGE_IN_DAYS": 1,
  "ACTIVE_COLLECTORS": "abuseipdb,otx,urlhaus"
}
```

`CONFIDENCE_MINIMUM`, `LIMIT_DETAILS` e `MAX_AGE_IN_DAYS` são usados pelo coletor do AbuseIPDB. `ACTIVE_COLLECTORS` define quais feeds estarão habilitados (separados por vírgula).
Para testes locais sem acessar a API, informe `ABUSE_MOCK_FILE` apontando para um JSON com o retorno esperado.

## Debug

Os logs sao gravados em `logs/` e tambem exibidos coloridos no terminal utilizando `rich`. Para aumentar a verbosidade, altere o nivel em `setup_logging()` para `DEBUG`.
