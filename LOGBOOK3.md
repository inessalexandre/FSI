
# Trabalho realizado na Semana #3

## CVE-2013-1763

## Identificação

- A vulnerabilidade foi encontrada através de um erro de índice de array na função _sock_diag_rcv_msg em net/core/sock_diag-c no Linux Kernel.
- Classificada com o tipo "Ganho de Privilégios" e com o CWE-20 (recebe input mas não valida corretamente se o input tem as propriedades necessárias para processar dados de forma segura e correta).
- Um atacante poderia utilizar esta vulnerabilidade para colapsar programas ou corrê-los como administrador.
- Esta vulnerabilidade afeta 180 versões do Linux Kernel desde a versão 3.3 até à versão 3.8.

## Catalogação

- Esta vulnerabilidade foi reportada por Mathias Krause, a 23 de fevereiro de 2013.
- De acordo com o NIST ("National Institute of Standards and Technology"), apresenta um score de 7.2/10.
- Resulta numa perda completa de confidencialidade e integridade no sistema , culminando num total shutdown dos recursos afetados.
- Para além de não ser necessário qualquer tipo de autenticação, esta vulnerabilidade não requer competências ou abilidades técnicas para ser executada. 

## Exploit

- Para realizar este ataque, deve ser enviada uma mensagem netlink a solicitar SOCK_DIAG_BY_FAMILY com uma familia maior ou igual a AF_MAX (o tamanho do array sock_diag_handlers[]).
- O código atual não testa esta condição, pelo que é vulnerável a um acesso out-of-bounds dando privilégios além do pretendido ou autorizado aos utilizadores.

## Ataques

- A vulnerabilidade foi descoberta e relatada antes que algum ataque ou dano tivesse sido causado ou reportado.
