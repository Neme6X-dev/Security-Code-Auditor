# Rapport d'Audit de Securite

**Date :** 2025-07-12 14:30 UTC
**Repertoire analyse :** `./vulnerable_sample_project`
**Fichiers examines :** 12

---

## Resume

| Severite | Nombre |
|----------|--------|
| Critique | 2 |
| Haute | 2 |
| Moyenne | 1 |
| Basse | 0 |
| Info | 0 |
| **Total** | **5** |

---

## Findings

### 1. Injection de commande via system()

- **Regle :** `command-injection-system`
- **Severite :** Critique (CVSS ~9.8)
- **Fichier :** `src/exec.c:15`
- **Source :** semgrep
- **Confiance LLM :** high

**Explication :**

La variable user_cmd est injectee directement dans un appel a system() sans aucun filtrage. Un attaquant peut injecter des commandes arbitraires en utilisant des operateurs shell (;, |, &&, etc.). Par exemple, l'entree "legitimate; rm -rf /" executerait la commande destructive. La fonction system() invoque un shell /bin/sh -c, ce qui rend l'injection systematiquement possible.

**Patch suggere :**

```diff
- system(command);
+ char *args[] = {"echo", user_cmd, NULL};
+ execve("/bin/echo", args, NULL);
```

---

### 2. Buffer overflow via strcpy sans bornage

- **Regle :** `dangerous-strcpy`
- **Severite :** Critique (CVSS ~9.1)
- **Fichier :** `src/parser.c:42`
- **Source :** semgrep
- **Confiance LLM :** high

**Explication :**

La fonction strcpy() copie la chaine source dans le buffer destination sans verifier que la source tient dans la place disponible. Un attaquant peut fournir une chaine plus longue que le buffer alloue (ici 64 octets), ecrivant au-dela de ses limites et ecrasant potentiellement le retour de fonction ou d'autres variables sur la pile. Cette vulnerabilite est exploitable via une entree utilisateur non controlee.

**Patch suggere :**

```diff
- strcpy(buffer, user_input);
+ strncpy(buffer, user_input, sizeof(buffer) - 1);
+ buffer[sizeof(buffer) - 1] = '\0';
```

---

### 3. Buffer overflow potentiel via sprintf

- **Regle :** `dangerous-sprintf`
- **Severite :** Haute (CVSS ~7.1)
- **Fichier :** `src/format.c:34`
- **Source :** semgrep
- **Confiance LLM :** high

**Explication :**

sprintf() ecrit dans le buffer destination sans limite de taille. Si la chaine formatee depasse la capacite du buffer, un overflow se produit. Contrairement a snprintf(), sprintf() ne verifie pas la taille disponible, ce qui en fait une source classique de vulnerabilites.

**Patch suggere :**

```diff
- sprintf(buffer, format, data);
+ snprintf(buffer, sizeof(buffer), format, data);
```

---

### 4. Fuite memoire : malloc sans free correspondant

- **Regle :** `memleak`
- **Severite :** Haute (CVSS ~7.5)
- **Fichier :** `src/utils.c:87`
- **Source :** cppcheck
- **Confiance LLM :** medium

**Explication :**

Le bloc de memoire alloue via malloc() a la ligne 87 n'est jamais libere par un appel a free(). Dans un programme serveur longuement executant, ces fuites s'accumulent et peuvent conduire a un denial of service par exhaustion memoire (OOM). Meme dans un programme court, cela constitue une mauvaise pratique qui peut etre exploitee dans certains contextes.

**Patch suggere :**

```diff
+ char *data = (char *)malloc(size);
  if (data == NULL) { return; }
  /* ... utilisation de data ... */
+ free(data);
```

---

### 5. Retour de fork() non verifie

- **Regle :** `unchecked-fork-return`
- **Severite :** Moyenne (CVSS ~5.5)
- **Fichier :** `src/server.c:120`
- **Source :** semgrep
- **Confiance LLM :** medium

**Explication :**

fork() retourne -1 en cas d'echec, 0 dans le processus fils, et le PID du fils dans le processus pere. Si le retour n'est pas verifie, le programme peut continuer avec un PID de 0 ou -1, conduisant a un comportement indefini. En particulier, un appel subsequent a exit() dans le code du fils terminerait aussi le pere.

**Patch suggere :**

```diff
+ pid_t pid = fork();
+ if (pid < 0) {
+     perror("fork");
+     exit(EXIT_FAILURE);
+ }
+ if (pid == 0) {
+     /* code du fils */
+ }
```

---
