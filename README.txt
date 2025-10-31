-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

Grupo - Tomás Alexandre 73213, Nicolae Iachimovschi 73381

Olá professor, aqui tem um ficheiro README que dá as insruções de como rodar o código.
No nosso computador nós seguimos estes passos, esperemos que funcione no seu tambem!

SE PEDIR PASWORD INSERIR - 123

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 1. Gerar certificados TLS (ligação segura cliente-servidor) -> começamos por gerar estes certificados que vão aparecer utonomaticamente na pasta. 

keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -keystore serverkeystore.jks -storepass changeit -keypass changeit -dname "CN=localhost, OU=Dev, O=Dev, L=City, S=State, C=PT" -validity 3650

keytool -exportcert -alias server -keystore serverkeystore.jks -storepass changeit -rfc -file server.cer

keytool -importcert -alias server -file server.cer -keystore clienttruststore.jks -storepass changeit -noprompt

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 2. Compilar os ficheiros Java 

javac *.java

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 3. Executar o servidor 

java BlockStorageServer

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

IMPORTANTE ----> Tem de criar um terminal separado ao do server

## 4. Executar o cliente - NOTA que o client normal vem com um menu interativo que apenas precisa de escolhar as opções de 1 a 7.

java BlockStorageClient

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

IMPORTANTE ----> Tem de criar um terminal separado ao do server

## 5. Executar o cliente de teste - para usar este cliente precisa de usar os seguintes comandos:

java ClTest

java ClTest PUT <ficheiro> <kw1,kw2,...>
java ClTest GET <ficheiro|keyword> [destino]
java ClTest SEARCH <keyword>
java ClTest LIST
java ClTest CHECKINTEGRITY <ficheiro>

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 7. Testar com um ficheiro de exemplo --> pizza.txt

NOTA: Criamos um ficheiro exemplo chamado "pizza.txt", o professor pode usar esse ficheiro ou se quiser pode criar um novo, ou utilizar uma imagem.

java ClTest PUT client/clientfiles/pizza.txt receita
java ClTest LIST
java ClTest SEARCH receita
java ClTest GET pizza.txt 
java ClTest GET receita
java ClTest CHECKINTEGRITY pizza.txt        -----> Neste caso para dar falha, mude o conteudo do block que foi colocado no blockstorage

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 8. Encerrar o servidor

Para terminar o servidor, usa Ctrl + C. (no caso do client test), 
ou clicar na tecla 7 que corresponde ao sair do client nomal
