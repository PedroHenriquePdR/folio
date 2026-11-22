# Assinar uma cópia do PDF com certificado ICP-Brasil A1

O primeiro fluxo do fork usa um certificado A1 já importado de um arquivo PFX ou P12. O usuário abre o PDF no Folio para desktop, escolhe o certificado pelo titular, emissor e validade e confirma a criação de uma cópia assinada. A assinatura é incorporada ao PDF. A operação usa a chave no computador e dispensa outro aplicativo assinador.

## Etapas e critérios

- [x] Atualizar a base do fork por avanço rápido e isolar o desenvolvimento em uma branch.
- [x] Preparar a assinatura incremental conforme a política PAdES AD-RB v1.3. Conferir referências, intervalos de bytes e preservação do PDF original.
- [x] Consultar o repositório local de certificados e assinar com a chave selecionada. Conferir o CMS destacado com uma implementação independente e uma identidade de teste.
- [x] Ligar o menu, a seleção de identidade, a confirmação nativa e a criação da cópia. Testar cancelamento e erros pelo fluxo do aplicativo.
- [x] Integrar o assinador ao empacotamento do Windows, do macOS e do Linux e revisar as fronteiras. A matriz do fork executa os testes nativos por plataforma.
- [ ] Conferir o resultado de um certificado ICP-Brasil válido no portal VALIDAR. Essa etapa requer uma assinatura feita pelo titular.

## Decisões

A identificação local do certificado usa a impressão digital SHA-256 da folha. O processo nativo recebe uma solicitação por entrada padrão. A janela de confirmação identifica o documento e o certificado antes de usar a chave. A escolha e a senha do repositório duram apenas a operação.

A revisão do formato identificou que a política brasileira especifica nomes próprios para o filtro PDF e um hash interno da política. A integridade precisa ser conferida sobre os intervalos da assinatura, independentemente do componente que os gerou. Consulte o [guia do ITI para desenvolvedores](https://validar.iti.gov.br/guia-desenvolvedor.html) e o [repositório de políticas AD-RB do ITI](https://www.gov.br/iti/pt-br/assuntos/repositorio/assinatura-digital-com-referencia-basica-ad-rb).

## Evidências

- No Ubuntu, um teste abriu a interface desktop, desbloqueou um banco NSS isolado com um A1 fictício importado de PKCS#12, selecionou a identidade e baixou a cópia. O OpenSSL verificou o CMS com a folha esperada. O teste automatizado de integridade alterou um byte do conteúdo coberto e obteve rejeição.
- O parser independente pdf-lib resolveu o campo de assinatura e os intervalos em PDFs com e sem streams de objetos. O qpdf aceitou a estrutura e o Poppler recuperou o texto original. Os casos de regressão incluem uma assinatura presente em revisão anterior e ocultada na revisão mais recente.
- A revisão encontrou duas condições de cancelamento. Recarregar a janela principal agora interrompe uma confirmação pendente. Mudar o documento enquanto o Folio prepara ou assina deixa de gerar um download tardio. As contraprovas falharam com o comportamento antigo e passaram com as correções.
- A revisão corrigiu a identificação de perfis A1 de pessoa física e jurídica e permitiu a confirmação nativa de uma chave Windows com proteção forte. A compilação cruzada verificou o executável Windows. A interação com esse prompt em um equipamento real continua pendente.
- A prova de empacotamento local conferiu a cópia do executável Linux e das licenças para a pasta de recursos. O workflow do fork verifica uma identidade descartável nos repositórios nativos e as duas arquiteturas do pacote universal para macOS.
