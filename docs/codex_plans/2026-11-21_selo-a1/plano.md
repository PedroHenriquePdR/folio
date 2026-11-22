# Selo visível para assinatura com A1

O titular escolheu um selo textual, visível por padrão, com CPF ou CNPJ completo quando o certificado identifica o titular de forma inequívoca. O fluxo parte da página atual e permite escolher outra página, posicionar o selo, ajustar o tamanho ou assinar uma cópia sem selo.

## Etapas

- [x] Extrair do A1 o nome e o documento do titular. Conferir pessoa física, pessoa jurídica, representante, dados ausentes e ambíguos.
- [x] Montar a prévia sobre a página e converter a posição escolhida para as coordenadas do PDF. Conferir clique, setas, tamanho, rotação, troca de página e cancelamento.
- [x] Vincular uma aparência imprimível ao próprio campo de assinatura antes de calcular os intervalos assinados. Preservar os bytes originais, as restrições de assinatura e a opção invisível.
- [x] Conferir a integração e a integridade em um repositório NSS isolado. Alterar um byte da aparência e verificar a rejeição pelo OpenSSL.
- [x] Revisar o resultado, executar os testes e atualizar o pacote local do Ubuntu. Verificar a cópia assinada a partir do aplicativo instalado.

## Contratos

A interface envia o número da página a partir de 1 e os quatro limites do retângulo no sistema de coordenadas do PDF. O processo principal consulta novamente o A1 escolhido antes da confirmação nativa e determina o instante da assinatura. O processo de PDF recebe a geometria e os dados públicos de apresentação e desenha o selo com o texto usado pela prévia.

Base do fork na branch `ci/icp-brasil-a1` em `7e025e2`. A autorização para atualizar o fork e o pacote local consta dos pedidos “Pode publicar”, “Atualize meu repositório” e “Instalar o Folio A1”. A prova de integridade usa credenciais fictícias. O aceite com um certificado pessoal no VALIDAR depende de uma assinatura do titular.

## Provas

Os testes da listagem cobriram CPF, CNPJ numérico e alfanumérico, dados do representante, documentos presentes no nome e campos incompletos ou contraditórios. No Ubuntu, um PKCS#12 fictício importado no NSS assinou um PDF de duas páginas com o selo na segunda. O OpenSSL confirmou o CMS com o certificado de teste e o rejeitou com um único byte alterado no conteúdo da aparência. Uma segunda prova com um A1 de empresa conferiu o CNPJ impresso e a ausência do CPF do representante.

Uma comparação de pixels nas quatro rotações verificou a orientação das letras e o retângulo escolhido. Os testes também exercitaram a herança dos limites da página, a unidade de medida do documento e as listas de anotações compartilhadas. O teste do limite fracionário reproduziu um erro de arredondamento antes da correção. Com a correção, a borda desenhada coincide com a área visível da página.

A revisão independente identificou uma diferença entre um campo de formulário preenchido e sua prévia. O diálogo passou a usar os mesmos bytes para mostrar e assinar o documento. O teste incluiu o valor preenchido e uma nota em outra página. O cancelamento durante a preparação descartou a solicitação pendente.

No Ubuntu passaram os 274 testes da aplicação, os 29 testes de PDF, serviço e integração, a suíte Go, a checagem de tipos, o build e o smoke completo. A verificação adicional em Chromium confrontou cada linha e posição vertical da prévia com a fonte usada para gravar o PDF. A suíte Go cobriu 45 cenários de identificação do titular. A compilação cruzada produziu o executável Windows x64.

O APT atualizou o pacote local `folio-a1` para `1.16.1~a1.20261121.gbb824e45`. A verificação dos arquivos instalados e do atalho passou. No aplicativo instalado, uma identidade fictícia assinou uma cópia por meio da confirmação nativa. O teste reabriu a cópia no Folio, conferiu o CMS com a folha esperada no OpenSSL e comparou a posição do selo com o clique na segunda página girada. A renderização do Poppler e a impressão em PDF reproduziram o mesmo retângulo, preservando a primeira página.

A tentativa de disparar a CI do fork retornou HTTP 422. O GitHub informou que o Actions está desativado para a conta. A execução nativa no Windows e no macOS e a conferência oficial com um A1 do titular continuam pendentes.
