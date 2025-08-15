# tmux — Chuleta rápida

Tabla de atajos y comandos útiles de **tmux**.

| Acción | Comando / Atajo | Notas |
|---|---|---|
| Iniciar tmux | `tmux` | Nueva sesión anónima. |
| Crear sesión con nombre | `tmux new -s SESION` | Desde la shell. |
| Listar sesiones | `tmux ls` |  |
| Adjuntar a sesión | `tmux attach -t SESION` | Atajo: `tmux a -t SESION`. |
| Desadjuntar (detach) | `Ctrl-b` `d` | Deja la sesión corriendo. |
| Renombrar sesión | `Ctrl-b` `$` | O `tmux rename-session -t viejo nuevo`. |
| Matar sesión | `tmux kill-session -t SESION` |  |
| Nueva ventana | `Ctrl-b` `c` | “Window” = pestaña. |
| Listar/seleccionar ventanas | `Ctrl-b` `w` | Selector interactivo. |
| Ir a sig./ant. ventana | `Ctrl-b` `n` / `Ctrl-b` `p` | También `Ctrl-b` `0..9`. |
| Renombrar ventana | `Ctrl-b` `,` |  |
| Cerrar ventana | `Ctrl-b` `&` |  |
| Split vertical | `Ctrl-b` `%` | Paneles (“panes”). |
| Split horizontal | `Ctrl-b` `"` |  |
| Mover entre paneles | `Ctrl-b` + ← ↑ → ↓ |  |
| Redimensionar panel | `Ctrl-b` `:` `resize-pane -L/-R/-U/-D 5` | Repite para más tamaño. |
| Cerrar panel | `Ctrl-b` `x` |  |
| Intercambiar paneles | `Ctrl-b` `{` / `Ctrl-b` `}` | Mueve panel a la izq./dcha. |
| Mostrar números de panel | `Ctrl-b` `q` | Pulsa número para saltar. |
| Convertir panel→ventana | `Ctrl-b` `!` | Extrae el panel a nueva ventana. |
| Sincronizar paneles (on/off) | `Ctrl-b` `:` `set -w synchronize-panes on` | Usa `off` para desactivar. |
| Copiar (copy-mode) | `Ctrl-b` `[` | Navega; `Space` inicia selección; `Enter` copia. |
| Pegar del buffer | `Ctrl-b` `]` |  |
| Buscar en copy-mode | `/` o `?`, luego `n`/`N` | Dentro de copy-mode. |
| Modo árbol (sesiones/ventanas) | `Ctrl-b` `s` | “choose-tree”. |
| Mostrar ayuda | `Ctrl-b` `?` | Lista de atajos. |
| Recargar configuración | `tmux source-file ~/.tmux.conf` | O `Ctrl-b` `:` `source-file ~/.tmux.conf`. |
| Enviar tecla a panel | `Ctrl-b` `:` `send-keys 'comando' Enter` | Útil en scripts. |

> Prefijo por defecto: `Ctrl-b`. Puedes cambiarlo en `~/.tmux.conf`, por ejemplo: `set -g prefix C-a` y `unbind C-b`.
