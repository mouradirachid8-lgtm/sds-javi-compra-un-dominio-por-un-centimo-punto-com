# Sprout - Proyecto Base para Prácticas en Go

Este proyecto es un *scaffold* deliberadamente simple para prácticas: incluye un servidor HTTP con una API JSON mínima, un cliente de terminal y un sistema de persistencia tipo clave/valor basado en `bbolt`.

La idea es que el alumnado use este repositorio como punto de partida y vaya añadiendo **funcionalidad** y **seguridad** según el enunciado de la práctica.

---

ESTE SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA, INCLUYENDO PERO NO LIMITADO A GARANTÍAS DE COMERCIABILIDAD, IDONEIDAD PARA UN PROPÓSITO PARTICULAR Y NO INFRACCIÓN. EN NINGÚN CASO LOS AUTORES O TITULARES DEL COPYRIGHT SERÁN RESPONSABLES POR NINGÚN RECLAMO, DAÑOS U OTRAS RESPONSABILIDADES, YA SEA EN UNA ACCIÓN CONTRACTUAL, AGRAVIO O DE OTRO TIPO, QUE SURJA DEL USO O RELACIONADO CON EL SOFTWARE.

---

## Estructura del Proyecto

A continuación, se detallan los principales componentes:

1. **main.go**: Inicia el servidor y el cliente en goroutines separadas.
2. **pkg/api/api.go**: Define la interfaz de comunicación (API JSON) entre cliente y servidor.
3. **pkg/client/client.go**: Maneja la interacción con el usuario y realiza solicitudes a la API.
4. **pkg/server/server.go**: Contiene la lógica del servidor HTTP para atender las peticiones.
5. **pkg/store/store.go**: Ofrece la interfaz de persistencia.
6. **pkg/store/bbolt.go**: Implementación concreta basada en `bbolt`.
7. **pkg/ui/ui.go**: Proporciona funciones para la interfaz de usuario en la terminal.

---

## Qué hace este repositorio

- Cliente de terminal con un menú básico.
- Servidor HTTP con endpoint `POST /api` y mensajes JSON.
- Registro/login/logout y lectura/escritura de un string asociado al usuario.
- Persistencia en disco con `bbolt` (carpeta `data/`).

---

## Qué NO hace (a propósito)

Este repositorio NO pretende ser una solución segura ni completa. Por diseño, faltan (o se simplifican) puntos que el alumnado debe implementar en la práctica, por ejemplo:

- Contraseñas sin PBKDF/sal (se guardan en claro).
- Tokens inseguros (predecibles) y sin expiración real.
- Comunicación por HTTP en claro (sin TLS).
- Sin cifrado en descanso (datos en la DB sin proteger).
- Sin funcionalidad adicional, gestión de roles o permisos, etc.

---

## Uso de los ejemplos proporcionados

Junto con este proyecto se facilitan ejemplos independientes (cifrado, HTTPS, PKI, subida de ficheros, etc.). La intención es que se utilicen como referencia y se adapten a la arquitectura de Sprout, no que se copien tal cual.

---

## Arquitectura y puntos de extensión

El diseño está pensado para que sea sencillo añadir funcionalidad sin reescribir todo el proyecto:

- La comunicación cliente-servidor está centralizada en `pkg/api`.
- La lógica HTTP está en `pkg/server`.
- La persistencia está abstraída en `pkg/store`.
- El cliente de terminal está en `pkg/client`.

Las modificaciones relacionadas con seguridad deberían intentar respetar esta separación de responsabilidades.

---

## Instalación y Uso

1. Instala Go en tu sistema.
2. Clona este repositorio.
3. Para ejecución rápida:
   ```
   go run main.go
   ```
4. Para compilar generando un ejecutable con nombre propio (en este caso *sprout*):
   ```
   go build -o sprout
   ```
   Luego ejecuta el binario generado (`./sprout` en Linux/macOS o `sprout.exe` en Windows).

---

## Desarrollo

- Tests (todos):
  ```
  go test ./...
  ```

- Fuzz tests (ejemplo):
  ```
  go test -fuzz=Fuzz -fuzztime=5s ./pkg/store
  ```