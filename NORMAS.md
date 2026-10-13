# Normas del reto «Incidente en el GSEC»

## 1. Los datos

- El conjunto de datos es **sintético y ficticio**. Se entrega exclusivamente para este reto: no
  puede publicarse, redistribuirse ni usarse para otros fines fuera del evento. Podéis conservar
  vuestro código; borrad los datos al terminar si la organización lo pide.
- Los datos son **hostiles a propósito**: contienen cadenas pensadas para romper analizadores,
  visores web y asistentes de IA, además de pistas falsas plantadas. Tratadlos como entrada no
  confiable en todo lo que construyáis.
- Ninguna IP pública, dominio, persona, cuenta o producto del dataset es real. No intentéis
  resolver, visitar ni contactar nada de lo que aparece en los datos.
- Si creéis haber encontrado un **error** del dataset (no una trampa), avisad a la organización:
  la corrección, si procede, se publica para todos los equipos a la vez.

## 2. Equipos y herramientas

- Equipos de **4 a 5 personas** (mínimo 4, máximo 5). Cada miembro necesita una cuenta de GitHub:
  el acceso al repositorio de entrega se concede por usuario. Todo el trabajo se realiza durante la
  ventana del evento, salvo la lectura del enunciado y la preparación del entorno (instalar
  herramientas, crear cuentas).
- **Libertad total de herramientas**, incluidos asistentes de IA. Sois responsables de lo que
  entregáis: una respuesta inventada por un asistente a partir de una pista falsa cuenta como
  trampa. Documentad en la bitácora qué herramientas habéis usado y para qué.
- Está permitido reutilizar bibliotecas y plantillas públicas, citándolas. No está permitido
  compartir respuestas, consultas ni datos derivados con otros equipos durante el evento.

## 3. Entregas y plazos

- Todo se entrega en el **repositorio privado de entrega** de cada equipo. La organización y el
  jurado tienen acceso de lectura; nadie más.
- `respuestas.json` y `oleadaN.json` tienen **formato obligatorio** (ver
  `starter-kit/FORMATO_ENTREGA_ES.md`). Un fichero que no valide no puntúa. El repositorio de
  entrega os avisa en cada *push*; también podéis validar en local con
  `starter-kit/validar_respuestas.py`.
- **Marca temporal:** cuenta la hora del *push* registrada por GitHub, no la de vuestro
  ordenador. No reescribáis el historial (`push --force`) del repositorio de entrega: se trata
  como entrega inválida.
- **Cierre del cuestionario y de los reportes de oleada: jueves 15/10/2026 19:30 (hora peninsular).** Los cambios
  posteriores en esos ficheros no se tienen en cuenta. El informe, el resumen ejecutivo y el
  plan de respuesta pueden actualizarse hasta el inicio de las presentaciones.
- Para el reto A (detección en vivo), cada oleada se reporta en su propio fichero
  (`oleada1.json`, `oleada2.json`, `oleada3.json`). Se puntúa la **primera versión válida** de
  cada fichero: podéis corregirla después, pero el tiempo de detección es el del primer *push*.
  Reportar como ataque una oleada que no lo es **resta**.

## 4. Puntuación y penalizaciones

- El sistema de puntuación completo lo publica la organización en el enunciado del evento. En el
  cuestionario: **+1 por acierto, 0 en blanco (`null`), −1 por respuesta-trampa**, máximo 10.
  En blanco nunca resta: si no estáis seguros, no adivinéis.
- Las vulnerabilidades de vuestra consola explotables con los propios datos del reto (XSS con un
  user-agent, inyección SQL en un filtro, etc.) restan en el reto 2.
- Desempates: menor tiempo medio de detección en el reto A; después, mejor cuestionario.

## 5. Reglas de enfrentamiento

- **No se ataca nada que no sea vuestro.** Ni la infraestructura de la organización, ni los
  despliegues de otros equipos, ni los dominios o IP del dataset (que, además, son ficticios).
- El jurado probará vuestras consolas con los datos del reto y con entradas manipuladas, siempre
  dentro de la ventana de evaluación y sin denegación de servicio.
- Las credenciales que compartáis en `ENTREGA.md` deben ser exclusivas para el reto. No reutilicéis
  contraseñas personales.

## 6. Convivencia

- Respeto entre equipos, mentores y organización. Las conductas inapropiadas suponen la
  descalificación.
- Si algo del escenario os incomoda o detectáis un problema (de datos, de accesibilidad, de
  trato), decídselo a la organización: el canal de la organización del Malackathon (por confirmar).
