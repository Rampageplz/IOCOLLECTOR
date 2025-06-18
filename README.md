# TestAPI

Este repositório contém o script `ioc_collector/app.py` que coleta IPs
da blacklist do AbuseIPDB e consulta detalhes adicionais em outros
endpoints da API (check e reports). A cada execução são buscados os
relatórios recentes dos IPs coletados para maximizar a correlação de
dados de ameaças.

Ao executar o script, ele obtém os IPs reportados nas últimas 24 horas com
`abuseConfidenceScore` maior ou igual a 80, consulta os endpoints `check`
e `reports` para cada IP e em seguida salva os indicadores em arquivos
JSON consolidados em `alerts.json`. No final da execução são exibidos os
IPs mais reportados no próprio dia.

Execute a coleta com:

```bash
python ioc_collector/app.py
```

Para ver os IPs mais reportados de uma data específica, utilize:

```bash
python ioc_collector/app.py --top AAAA-MM-DD
```
