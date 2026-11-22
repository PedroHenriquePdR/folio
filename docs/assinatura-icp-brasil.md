# Assinar um PDF com seu certificado A1

Na versão desktop deste fork, o Folio usa um A1 ICP-Brasil já instalado para gerar uma cópia assinada do PDF. Você importa o arquivo `.pfx` ou `.p12` com a chave privada uma vez. O Folio usa o repositório de certificados do computador a cada assinatura.

## Onde instalar

| Sistema | Repositório lido pelo Folio |
| --- | --- |
| Windows | **Pessoal** do **Usuário Atual**. Ao importar o PFX, escolha esse usuário e esse repositório. |
| Ubuntu e outras distribuições Linux | Banco NSS compartilhado usado pelo Chromium. Se a pasta `~/.pki/nssdb` existir, ela tem precedência. Nas instalações mais recentes, o caminho é `$XDG_DATA_HOME/pki/nssdb` ou `~/.local/share/pki/nssdb`. Um perfil exclusivo do Firefox pode usar outro banco. |
| macOS | Chaveiro do usuário. Importe o arquivo no Acesso às Chaves e confira se o certificado aparece em **Meus Certificados** com a chave privada associada. |

## Como assinar nesta branch

1. Abra um PDF no Folio para desktop e escolha **More → Sign with a certificate**.
2. Se o banco NSS pedir a senha, informe a senha desse banco. Selecione o certificado pelo titular, emissor e vencimento.
3. O selo visível vem ativado. Na prévia, escolha a página e clique onde deseja colocá-lo. Para mudar a posição, clique em outro ponto ou use as setas com a prévia em foco. O controle de tamanho ajusta a área do selo. Para assinar sem marca na página, desmarque a opção de selo visível.
4. Clique em **Sign copy**. Confira o documento, o certificado e a página na confirmação do sistema. Ao confirmar, o Folio gera uma cópia com o sufixo `(signed).pdf`.

O selo aparece no PDF e na impressão. Ele exibe o nome do titular e o horário da assinatura com o fuso. Se o A1 identificar o documento do titular de forma inequívoca, o selo também exibirá o CPF completo da pessoa física ou o CNPJ completo da empresa. Esse dado ficará visível para quem receber a cópia. A aparência faz parte do conteúdo protegido pela assinatura digital. Se a fonte do selo não contiver um caractere do nome, o Folio permite prosseguir com a opção de assinatura sem selo.

Esta primeira versão acrescenta a primeira assinatura digital ao documento. O PDF mantém o conteúdo original e recebe uma revisão que contém a assinatura. Formulários comuns e anotações são preservados. Para reorganização de páginas, edição do conteúdo ou inclusão de texto pesquisável gerado por OCR, use **Save a copy** e reabra a cópia antes de assinar. Documentos já assinados, criptografados, PDF/A-1 e formulários XFA ou com requisitos de assinatura específicos ficam fora desse fluxo. A assinatura digital pode ser conferida mesmo sem marca visível na página.

## Conferência pelo titular

Para o primeiro teste, use um PDF de exemplo, assine com seu A1 e envie **somente a cópia assinada** ao VALIDAR. Confira a identidade do signatário e o resultado da verificação. O arquivo PFX, sua senha e a senha do repositório ficam com o titular. O Folio não envia o PDF ao portal. [VALIDAR do ITI](https://validar.iti.gov.br/)

O formato implementado é PAdES ICP-Brasil com a política AD-RB v1.3. Nos testes automatizados o OpenSSL confere a assinatura com um certificado fictício e detecta uma alteração posterior nos bytes assinados. A confirmação de conformidade no ITI depende de um documento assinado com um certificado real da cadeia ICP-Brasil. [Guia de orientações aos desenvolvedores do ITI](https://validar.iti.gov.br/guia-desenvolvedor.html)

## Executar pelo código-fonte

Esta versão está na branch `ci/icp-brasil-a1`. Para executá-la em um checkout novo, use Node.js 22, Go 1.26.11 e um compilador C compatível com o sistema. No macOS o build usa as ferramentas de linha de comando do Xcode. No Windows o build nativo usa MinGW. No Linux o sistema precisa ter a biblioteca NSS softokn.

```sh
git clone --branch ci/icp-brasil-a1 https://github.com/PedroHenriquePdR/folio.git folio-a1
cd folio-a1
npm ci
npm run app
```

O assinador nativo é compilado junto com o aplicativo de desenvolvimento. A distribuição instalada inclui esse executável. A publicação dos instaladores e o canal de atualizações do fork ficam para uma etapa posterior.
