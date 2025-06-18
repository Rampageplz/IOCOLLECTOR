# IOC Collector

Este projeto realiza a coleta diaria de indicadores de comprometimento (IOCs) a partir da API do [AbuseIPDB](https://www.abuseipdb.com/). A estrutura foi modularizada para facilitar a manutencao e expansao.

## Estrutura

- `ioc_collector/collectors/collector_abuse.py` - funcoes para interagir com a API do AbuseIPDB
- `ioc_collector/alerts_manager.py` - gerencia o arquivo `alerts.json`
- `ioc_collector/utils/utils.py` - utilidades diversas
- `ioc_collector/main.py` - ponto de entrada da aplicacao
- `data/abuseipdb/` - arquivos diarios de IOCs
- `logs/` - arquivos de log no formato `YYYY-MM-DD.log`

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

## Debug

Os logs sao gravados em `logs/` e tambem exibidos coloridos no terminal utilizando `rich`. Para aumentar a verbosidade, altere o nivel em `setup_logging()` para `DEBUG`.
