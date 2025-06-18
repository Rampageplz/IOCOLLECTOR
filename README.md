# IOC Collector

Este projeto realiza a coleta diária de indicadores de comprometimento (IOCs) a partir da API do [AbuseIPDB](https://www.abuseipdb.com/). A estrutura foi modularizada para facilitar a manutenção e expansão.

## Estrutura

- `ioc_collector/collectors/collector_abuse.py` - funcoes para interagir com a API do AbuseIPDB
- `ioc_collector/alerts_manager.py` - gerencia o arquivo `alerts.json`
- `ioc_collector/utils/utils.py` - utilidades diversas
- `ioc_collector/main.py` - ponto de entrada da aplicacao
- `data/abuseipdb/` - arquivos diarios de IOCs
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

3. Crie um arquivo `.env` dentro da pasta `ioc_collector/` contendo a variável
   `ABUSEIPDB_API_KEY` com sua chave da API.

4. Execute o coletor:

   ```bash
   python ioc_collector/main.py
   ```

5. Para exibir os IPs mais reportados em determinada data:

   ```bash
   python ioc_collector/main.py --top AAAA-MM-DD
   ```

### Configuração

A coleta utiliza o arquivo `config.json` para definir parâmetros de consulta ao AbuseIPDB:

```json
{
  "CONFIDENCE_MINIMUM": 80,
  "LIMIT_DETAILS": 100,
  "MAX_AGE_IN_DAYS": 1
}
```

`CONFIDENCE_MINIMUM` define o score mínimo para que um IP seja incluído na blacklist. `LIMIT_DETAILS` limita o número de IPs para os quais serão buscados detalhes adicionais e `MAX_AGE_IN_DAYS` controla o período de interesse dos relatórios.

## Debug

Os logs sao gravados em `logs/` e tambem exibidos coloridos no terminal utilizando `rich`. Para aumentar a verbosidade, altere o nivel em `setup_logging()` para `DEBUG`.
