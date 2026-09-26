# UltraShield · testemunha independente W2
Este repositório é PÚBLICO de propósito: qualquer pessoa pode ler o código da testemunha e conferir o histórico de assinaturas (`cosign.json`).
Ela baixa a cadeia pública de batimentos do UltraShield, confere tudo sozinha e assina, com uma chave própria, a cabeça da cadeia que viu.
Regra: nunca assina duas cabeças diferentes para a mesma época. A chave pública fica no verificador público. Não guarda nenhum dado de cliente.
