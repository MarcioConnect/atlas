# Contribuindo com o ATLAS

Obrigado pelo interesse. Este projeto é uma ferramenta de segurança defensiva;
contribuições que quebrem a postura somente leitura ou o mascaramento de segredos
não serão aceitas.

Antes de participar, leia o [Código de Conduta](CODE_OF_CONDUCT.md) e a
[Política de Segurança](SECURITY.md).

## Ambiente de desenvolvimento

Use Python 3.11 ou superior no Windows. Crie um ambiente virtual e instale as
dependências de desenvolvimento:

```powershell
python -m pip install -e ".[dev]"
```

## Verificações obrigatórias

Execute antes de abrir um pull request:

```powershell
python -m pytest
python -m ruff check src tests
```

## Diretrizes

- Mantenha o watcher somente leitura e preserve o mascaramento de segredos.
- Garanta que falhas de scanners opcionais degradem com segurança.
- Novos adaptadores de scanner devem incluir testes para executável ausente,
  saída malformada e evidência sanitizada.
- Não inclua segredos, caminhos absolutos pessoais nem dados sensíveis no diff.
- Atualize o [README](README.md) e a documentação em `docs/` quando o
  comportamento mudar.

## Fluxo

1. Abra um branch a partir de `main`.
2. Faça commits pequenos e descritivos.
3. Garanta que os testes e o lint passam.
4. Abra um pull request usando o template e descreva a mudança e a issue
   relacionada.

## Reportando problemas

Use os templates de issue em `.github/ISSUE_TEMPLATE`. Para vulnerabilidades,
abra um GitHub Security Advisory privado, conforme a [Política de Segurança](SECURITY.md).
