# Contribuindo com o ATLAS

Obrigado por querer ajudar no ATLAS. Correções, documentação e ideias são
bem-vindas. Como a ferramenta analisa projetos de outras pessoas, toda mudança
precisa preservar o modo somente leitura e o cuidado com dados sensíveis.

Antes de participar, leia o [Código de Conduta](CODE_OF_CONDUCT.md) e a
[Política de Segurança](SECURITY.md).

## Ambiente de desenvolvimento

Use Python 3.11 ou superior no Windows. Crie um ambiente virtual e instale as
dependências de desenvolvimento:

```powershell
python -m pip install -e ".[dev]"
```

## Antes de abrir um pull request

Rode os testes e o lint antes de enviar sua mudança:

```powershell
python -m pytest
python -m ruff check src tests
```

## Diretrizes

- Mantenha o watcher somente leitura e preserve o mascaramento de segredos.
- Se um scanner opcional falhar, o ATLAS deve continuar funcionando e avisar
  sobre a cobertura reduzida.
- Novos adaptadores de scanner devem incluir testes para executável ausente,
  saída malformada e evidência sanitizada.
- Não inclua segredos, caminhos absolutos pessoais nem dados sensíveis no diff.
- Atualize o [README](README.md) e a documentação em `docs/` quando o
  comportamento mudar.

## Fluxo

1. Crie um branch a partir de `main`.
2. Faça commits pequenos, com mensagens que expliquem a mudança.
3. Confirme que os testes e o lint passam.
4. Abra um pull request pelo template. Explique o que mudou e, se houver, faça
   referência à issue relacionada.

## Reportando problemas

Para bugs e sugestões, use um dos templates em `.github/ISSUE_TEMPLATE`. Se
encontrar uma vulnerabilidade, reporte-a por um GitHub Security Advisory
privado, conforme a [Política de Segurança](SECURITY.md).
