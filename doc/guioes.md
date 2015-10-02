# Guiões das Sessões Laboratoriais

---
## Semana 2

### Cifra de ficheiro utilizando JCA/JCE

Pretende-se cifrar o conteudo de um ficheiro. Para tal far-se-á uso da funcionalidade oferecida pela JCA/JCE, em particular implementação de cifras simétricas.

O objectivo é então o de definir um pequeno programa Java que permita cifrar/decifrar um ficheiro utilizando uma cifra simétrica (e.g. RC4). A sua forma de utilização pode ser análoga a:

```
prog -genkey <keyfile>
prog -enc <keyfile> <infile> <outfile>
prog -dec <keyfile> <infile> <outfile>
```

Sugestões:

 * Para simplificar, pode começar por utilizar uma chave secreta fixa definida no código na forma de um array de bytes (i.e. implementar somente as opções -enc e -dec). Nesse caso, deverá utilizar a classe SecretKeySpec para a converter para o formato adequado.
 * Um segundo passo deverá consistir na implementação da opção -genkey. Aí surge o problema de guardar a chave no sistema de ficheiros: vamos começar por adoptar a solução mais simples (e insegura) - guardar a chave directamente num ficheiro sem qualquer tipo de protecção.

Algumas classes relevantes (ver [API](http://docs.oracle.com/javase/8/docs/api/)):

 * `javax.crypto.Cipher`
 *  `javax.crypto.KeyGenerator`
 * `javax.crypto.SecretKey (interface)`
 * `javax.crypto.spec.SecretKeySpec`
 * `java.security.SecureRandom`

---
## Semana 1

Os objectivos para a aula desta semana são:
 1. escolher e instalar o ambiente de programação _Java_ a utilizar nas aulas laboratoriais de Criptografia;
 1. familiarizar-se com os comandos essenciais do *GIT* por forma a interagir com o repositório pessoal e o da UC.
 1. registar-se no [GitHub](http://github.com) e criar o repositório que irá conter programas realizados ao longo do semestre;
 1. desenvolver um pequeno programa _Java_ para colocar no repositório pessoal e submeter a versão final para o repositório da UC.

### Apontadores úteis:
 * Linguagem de programação _Java_
   * [JDK SE](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
   * [Java API](http://docs.oracle.com/javase/8/docs/api/)
   * [Java tutorials](http://docs.oracle.com/javase/tutorial/)
 * *Git*
   * [site oficial](https://git-scm.com)
   * [TryIt!](http://try.github.io)
   * [GitHub's cheat sheet](https://training.github.com/kit/downloads/github-git-cheat-sheet.pdf), [Visual Git cheat sheet](http://ndpsoftware.com/git-cheatsheet.html)
   * [GitPro online book](https://git-scm.com/book/en/v2)
 * GitHub
   * <http://github.com> (signup, signin, etc.)
   * [GitHub desktop](https://desktop.github.com)
   * repositório da UC: <https://github.com/jba-uminho/mietium-crpt>

### Tarefas:
 1. *fork* do repositório da UC (ver [documentação](https://help.github.com/articles/fork-a-repo/))
 1. *clone" do repositório pessoal (ver https://help.github.com/articles/cloning-a-repository/)
 1. crie em `src/mycat` uma aplicação Java que se comporte como o comando *Unix* `cat` (i.e. copie o conteúdo de `stdin` para `stdout`)
 1. faça `commit`, `push`, etc. frequentemente por forma a manter o repositório pessoal actualizado
 1. quando finalizar o programa, submeta o programa realizado por intermédio de um `PullRequest` do GitHub (ver https://help.github.com/articles/using-pull-requests/)

---
