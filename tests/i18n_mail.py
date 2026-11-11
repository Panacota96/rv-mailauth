"""Adds the rv-mailauth finding codes, limitations and report labels to i18n/{en,es,fr}.json.

Idempotent: run it after editing the wording below (python tests/i18n_mail.py). The catalogues stay the
single source of the wording; this script only keeps the three languages in step.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

F = {}  # code -> {lang: (title, shows, does_not_prove)}


def f(code, en, es, fr):
    F[code] = {"en": en, "es": es, "fr": fr}


f("DKIM_BODY_HASH_MISMATCH",
  ("DKIM body hash does not match",
   "The DKIM signature of %{d} (selector %{s}) records a hash of the message body that differs from the hash of the body as it is now: the body is not the one that was signed.",
   "It does not show who changed the body, when, or why: forwarding systems, mailing lists, antivirus footers and re-encoding by a mail client also change bodies after signing."),
  ("El hash del cuerpo DKIM no coincide",
   "La firma DKIM de %{d} (selector %{s}) registra un hash del cuerpo del mensaje distinto del hash del cuerpo actual: el cuerpo no es el que se firmó.",
   "No indica quién cambió el cuerpo, cuándo ni por qué: reenvíos, listas de correo, pies de antivirus y la recodificación por un cliente de correo también cambian el cuerpo después de la firma."),
  ("Empreinte DKIM du corps non concordante",
   "La signature DKIM de %{d} (sélecteur %{s}) enregistre une empreinte du corps du message différente de celle du corps actuel : le corps n'est pas celui qui a été signé.",
   "Cela n'indique ni qui a modifié le corps, ni quand, ni pourquoi : transferts, listes de diffusion, mentions antivirus et réencodage par un client de messagerie modifient aussi le corps après la signature."))
f("DKIM_SIGNATURE_INVALID",
  ("DKIM signature does not verify",
   "The body matches the DKIM signature of %{d} (selector %{s}), but the signature over the signed header fields does not verify with the supplied public key (key source: %{key_source}; verifier: %{reason}).",
   "It does not show that a header was forged: a supplied key that is not the one used at sending time (keys are rotated), or a header rewritten in transit, gives the same result."),
  ("La firma DKIM no se verifica",
   "El cuerpo coincide con la firma DKIM de %{d} (selector %{s}), pero la firma de los campos de cabecera firmados no se verifica con la clave pública suministrada (origen de la clave: %{key_source}; verificador: %{reason}).",
   "No indica que se falsificara una cabecera: una clave suministrada que no es la usada en el momento del envío (las claves rotan) o una cabecera reescrita en tránsito dan el mismo resultado."),
  ("La signature DKIM ne se vérifie pas",
   "Le corps correspond à la signature DKIM de %{d} (sélecteur %{s}), mais la signature des en-têtes signés ne se vérifie pas avec la clé publique fournie (origine de la clé : %{key_source} ; vérificateur : %{reason}).",
   "Cela n'indique pas qu'un en-tête a été falsifié : une clé fournie qui n'est pas celle utilisée à l'envoi (les clés changent) ou un en-tête réécrit en transit donnent le même résultat."))
f("DKIM_KEY_FROM_CURRENT_DNS",
  ("DKIM key taken from today's DNS",
   "The key for %{d} (selector %{s}) was not in the examiner's key file and was fetched from the DNS at the time of the analysis (online mode).",
   "A key published today may not be the key that signed the message; a pass or a failure with it says nothing certain about the key valid at sending time."),
  ("Clave DKIM tomada del DNS actual",
   "La clave de %{d} (selector %{s}) no estaba en el archivo de claves del perito y se obtuvo del DNS en el momento del análisis (modo en línea).",
   "Una clave publicada hoy puede no ser la que firmó el mensaje; un resultado válido o inválido con ella no dice nada seguro sobre la clave vigente en el momento del envío."),
  ("Clé DKIM issue du DNS actuel",
   "La clé de %{d} (sélecteur %{s}) n'était pas dans le fichier de clés de l'expert et a été obtenue du DNS au moment de l'analyse (mode en ligne).",
   "Une clé publiée aujourd'hui peut ne pas être celle qui a signé le message ; un résultat valide ou invalide avec elle ne dit rien de certain sur la clé en vigueur lors de l'envoi."))
f("DKIM_DOMAIN_NOT_ALIGNED",
  ("Valid DKIM signature from another domain",
   "The message carries a valid DKIM signature only for %{d}, which does not share its organisational domain with the From domain %{from_domain}.",
   "Sending services, mailing lists and outsourced mail commonly sign with their own domain; it does not show that the From address was spoofed."),
  ("Firma DKIM válida de otro dominio",
   "El mensaje solo tiene una firma DKIM válida de %{d}, que no comparte dominio organizativo con el dominio del remitente (From) %{from_domain}.",
   "Los servicios de envío, las listas de correo y el correo externalizado suelen firmar con su propio dominio; no indica que el remitente se suplantara."),
  ("Signature DKIM valide d'un autre domaine",
   "Le message ne porte une signature DKIM valide que pour %{d}, qui ne partage pas son domaine organisationnel avec le domaine de l'expéditeur (From) %{from_domain}.",
   "Les services d'envoi, les listes de diffusion et la messagerie externalisée signent souvent avec leur propre domaine ; cela n'indique pas une usurpation de l'expéditeur."))
f("ARC_CHAIN_INVALID",
  ("ARC chain does not validate",
   "The message has %{instances} ARC set(s) and the chain does not validate (%{reason}).",
   "An intermediary may have broken the chain, or the keys of the sealers may not have been supplied; it does not show that the message was tampered with."),
  ("La cadena ARC no se valida",
   "El mensaje tiene %{instances} conjunto(s) ARC y la cadena no se valida (%{reason}).",
   "Un intermediario puede haber roto la cadena, o no se suministraron las claves de los selladores; no indica que el mensaje se manipulara."),
  ("La chaîne ARC ne se valide pas",
   "Le message comporte %{instances} jeu(x) ARC et la chaîne ne se valide pas (%{reason}).",
   "Un intermédiaire peut avoir rompu la chaîne, ou les clés des scelleurs n'ont pas été fournies ; cela n'indique pas une altération du message."))
f("RECEIVED_TIME_NOT_MONOTONIC",
  ("Received times go backwards",
   "Hop %{hop} was stamped %{hop_date}, %{earlier_by_s} s before the previous hop %{previous_hop} (%{previous_date}), beyond the tolerated clock difference (%{count} such step(s)).",
   "Server clocks are sometimes wrong and some servers add Received headers out of order; it does not show that a header was inserted or edited."),
  ("Las horas de Received retroceden",
   "El salto %{hop} se fechó %{hop_date}, %{earlier_by_s} s antes del salto anterior %{previous_hop} (%{previous_date}), más allá de la diferencia de reloj tolerada (%{count} paso(s) así).",
   "Los relojes de los servidores a veces fallan y algunos servidores añaden cabeceras Received fuera de orden; no indica que se insertara o editara una cabecera."),
  ("Les heures Received reculent",
   "Le saut %{hop} est daté %{hop_date}, %{earlier_by_s} s avant le saut précédent %{previous_hop} (%{previous_date}), au-delà de l'écart d'horloge toléré (%{count} étape(s) de ce type).",
   "Les horloges des serveurs sont parfois fausses et certains serveurs ajoutent les en-têtes Received dans le désordre ; cela n'indique pas qu'un en-tête a été inséré ou modifié."))
f("DATE_AFTER_FIRST_HOP",
  ("Date header later than the first server",
   "The Date header (%{date}) is %{later_by_s} s later than the time the first server received the message (%{first_hop_date}).",
   "The sender's clock may be wrong; it does not show that the date was changed after sending."),
  ("Cabecera Date posterior al primer servidor",
   "La cabecera Date (%{date}) es %{later_by_s} s posterior a la hora en que el primer servidor recibió el mensaje (%{first_hop_date}).",
   "El reloj del remitente puede estar mal; no indica que la fecha se cambiara después del envío."),
  ("En-tête Date postérieur au premier serveur",
   "L'en-tête Date (%{date}) est %{later_by_s} s plus tardif que l'heure à laquelle le premier serveur a reçu le message (%{first_hop_date}).",
   "L'horloge de l'expéditeur peut être fausse ; cela n'indique pas que la date a été modifiée après l'envoi."))
f("MSG_TRANSPORT_HEADERS_MISSING",
  ("Outlook message without transport headers",
   "The .msg file has no PR_TRANSPORT_MESSAGE_HEADERS property: the original header section (Received hops, DKIM signatures, Authentication-Results) is not available, so DKIM was not attempted.",
   "Drafts, sent items and messages saved by some tools never had these headers; it does not show that they were removed."),
  ("Mensaje de Outlook sin cabeceras de transporte",
   "El archivo .msg no tiene la propiedad PR_TRANSPORT_MESSAGE_HEADERS: la sección de cabeceras original (saltos Received, firmas DKIM, Authentication-Results) no está disponible, por lo que no se intentó DKIM.",
   "Los borradores, los elementos enviados y los mensajes guardados por algunas herramientas nunca tuvieron estas cabeceras; no indica que se eliminaran."),
  ("Message Outlook sans en-têtes de transport",
   "Le fichier .msg n'a pas de propriété PR_TRANSPORT_MESSAGE_HEADERS : la section d'en-têtes d'origine (sauts Received, signatures DKIM, Authentication-Results) n'est pas disponible, DKIM n'a donc pas été tenté.",
   "Les brouillons, les éléments envoyés et les messages enregistrés par certains outils n'ont jamais eu ces en-têtes ; cela n'indique pas qu'ils ont été supprimés."))
f("ATTACHMENT_DATE_AFTER_SENT",
  ("Attachment dated after the message",
   "The %{field} date of attachment %{attachment} (%{attachment_date}) is later than the message Date (%{date}).",
   "These dates are written by the sending client and are easy to get wrong or to set freely; it does not show that the attachment was swapped."),
  ("Adjunto con fecha posterior al mensaje",
   "La fecha de %{field} del adjunto %{attachment} (%{attachment_date}) es posterior a la fecha (Date) del mensaje (%{date}).",
   "Estas fechas las escribe el cliente que envía y es fácil que estén mal o se fijen libremente; no indica que el adjunto se sustituyera."),
  ("Pièce jointe datée après le message",
   "La date de %{field} de la pièce jointe %{attachment} (%{attachment_date}) est postérieure à la date (Date) du message (%{date}).",
   "Ces dates sont écrites par le client d'envoi et sont faciles à fausser ou à fixer librement ; cela n'indique pas que la pièce jointe a été remplacée."))
f("LOOKALIKE_DOMAIN",
  ("Domain resembles an own domain",
   "The %{header} domain %{domain} (%{domain_unicode}) resembles the own domain %{own_domain} (method: %{method}).",
   "Similar names also belong to legitimate, unrelated organisations; it does not show an intent to deceive."),
  ("Dominio parecido a un dominio propio",
   "El dominio de %{header} %{domain} (%{domain_unicode}) se parece al dominio propio %{own_domain} (método: %{method}).",
   "Nombres parecidos también pertenecen a organizaciones legítimas sin relación; no indica intención de engañar."),
  ("Domaine ressemblant à un domaine propre",
   "Le domaine %{header} %{domain} (%{domain_unicode}) ressemble au domaine propre %{own_domain} (méthode : %{method}).",
   "Des noms proches appartiennent aussi à des organisations légitimes sans lien ; cela n'indique pas une intention de tromper."))
f("REPLY_TO_DIFFERS",
  ("Replies go to another organisation",
   "The %{header} address %{address} does not share its organisational domain with the From domain %{from_domain}.",
   "Help desks, mailing lists, bulk senders and bounce handling legitimately use other addresses; it does not show that replies are being diverted."),
  ("Las respuestas van a otra organización",
   "La dirección %{header} %{address} no comparte dominio organizativo con el dominio del remitente %{from_domain}.",
   "Mesas de ayuda, listas de correo, envíos masivos y la gestión de rebotes usan legítimamente otras direcciones; no indica que se desvíen las respuestas."),
  ("Les réponses partent vers une autre organisation",
   "L'adresse %{header} %{address} ne partage pas son domaine organisationnel avec le domaine de l'expéditeur %{from_domain}.",
   "Les centres d'assistance, listes de diffusion, envois en masse et la gestion des retours utilisent légitimement d'autres adresses ; cela n'indique pas un détournement des réponses."))
f("DISPLAY_NAME_SPOOF",
  ("Display name suggests another sender",
   "The display name \"%{display_name}\" of %{address} contains another address or an own-organisation name while the address is external (%{reason}).",
   "People write names freely and partners mention the organisation they work with; it does not show impersonation."),
  ("El nombre visible sugiere otro remitente",
   "El nombre visible \"%{display_name}\" de %{address} contiene otra dirección o el nombre de la organización propia, aunque la dirección es externa (%{reason}).",
   "Los nombres se escriben libremente y los socios mencionan la organización con la que trabajan; no indica suplantación."),
  ("Le nom affiché suggère un autre expéditeur",
   "Le nom affiché « %{display_name} » de %{address} contient une autre adresse ou le nom de l'organisation propre alors que l'adresse est externe (%{reason}).",
   "Les noms s'écrivent librement et les partenaires mentionnent l'organisation avec laquelle ils travaillent ; cela n'indique pas une usurpation."))
f("FILE_STRUCTURE_DAMAGED",
  ("File structure damaged or incomplete",
   "The %{format} structure is not complete or not well formed (%{problems}); what could be read was analysed.",
   "Truncated copies, interrupted exports and non-standard writers cause this too; it does not show deliberate damage."),
  ("Estructura del archivo dañada o incompleta",
   "La estructura %{format} no está completa o no está bien formada (%{problems}); se analizó lo que se pudo leer.",
   "Las copias truncadas, las exportaciones interrumpidas y los programas no estándar también lo causan; no indica un daño deliberado."),
  ("Structure du fichier endommagée ou incomplète",
   "La structure %{format} n'est pas complète ou pas bien formée (%{problems}) ; ce qui a pu être lu a été analysé.",
   "Les copies tronquées, les exports interrompus et les logiciels non standard en sont aussi la cause ; cela n'indique pas un dommage volontaire."))
f("PARSER_FAILED",
  ("Message analysis not completed",
   "The analysis of this message did not complete (reason: %{reason}, exit code %{exit_code}); its email findings are missing.",
   "It does not show that the file is malicious or damaged; size limits, time limits and unusual content also stop an analysis."),
  ("Análisis del mensaje no completado",
   "El análisis de este mensaje no terminó (motivo: %{reason}, código de salida %{exit_code}); faltan sus hallazgos de correo.",
   "No indica que el archivo sea malicioso o esté dañado; los límites de tamaño o de tiempo y un contenido inusual también detienen un análisis."),
  ("Analyse du message non terminée",
   "L'analyse de ce message n'a pas abouti (motif : %{reason}, code de sortie %{exit_code}) ; ses constats de messagerie manquent.",
   "Cela n'indique pas que le fichier est malveillant ou endommagé ; des limites de taille ou de temps et un contenu inhabituel arrêtent aussi une analyse."))
f("DKIM_NOT_SIGNED",
  ("No DKIM signature",
   "The message carries no DKIM-Signature header.",
   "Many legitimate servers do not sign, and a missing signature is common; it proves nothing about authenticity either way."),
  ("Sin firma DKIM",
   "El mensaje no tiene cabecera DKIM-Signature.",
   "Muchos servidores legítimos no firman y la ausencia de firma es habitual; no demuestra nada sobre la autenticidad en ningún sentido."),
  ("Pas de signature DKIM",
   "Le message ne comporte pas d'en-tête DKIM-Signature.",
   "Beaucoup de serveurs légitimes ne signent pas et l'absence de signature est courante ; cela ne démontre rien sur l'authenticité, dans un sens ou dans l'autre."))
f("DKIM_SIGNATURE_NOT_EVALUATED",
  ("DKIM signature not evaluated",
   "The DKIM signature of %{d} (selector %{s}) could not be evaluated (%{reason}).",
   "An expired, unsupported or partial (l=) signature, or a .msg file whose original body is not stored, cannot be checked; it says nothing about the message."),
  ("Firma DKIM no evaluada",
   "La firma DKIM de %{d} (selector %{s}) no pudo evaluarse (%{reason}).",
   "Una firma caducada, no soportada o parcial (l=), o un archivo .msg que no guarda el cuerpo original, no puede comprobarse; no dice nada del mensaje."),
  ("Signature DKIM non évaluée",
   "La signature DKIM de %{d} (sélecteur %{s}) n'a pas pu être évaluée (%{reason}).",
   "Une signature expirée, non prise en charge ou partielle (l=), ou un fichier .msg qui ne conserve pas le corps d'origine, ne peut pas être vérifiée ; cela ne dit rien du message."))
f("TIMEZONE_INCONSISTENT",
  ("Time zone inconsistent",
   "The Date header uses zone %{date_zone} while the sender organisation's first server used %{hop_zone} (%{reason}).",
   "Clients and servers are often set to different zones, travellers keep their home zone; it does not show that the date was edited."),
  ("Zona horaria incoherente",
   "La cabecera Date usa la zona %{date_zone} mientras que el primer servidor de la organización remitente usó %{hop_zone} (%{reason}).",
   "Clientes y servidores suelen estar en zonas distintas y quien viaja conserva su zona; no indica que se editara la fecha."),
  ("Fuseau horaire incohérent",
   "L'en-tête Date utilise le fuseau %{date_zone} alors que le premier serveur de l'organisation expéditrice a utilisé %{hop_zone} (%{reason}).",
   "Clients et serveurs sont souvent réglés sur des fuseaux différents et les voyageurs gardent le leur ; cela n'indique pas une modification de la date."))
f("MESSAGE_ID_DOMAIN_MISMATCH",
  ("Message-ID from another domain",
   "The Message-ID was generated under %{message_id_domain}, not under the From domain %{from_domain}.",
   "Mail clients, sending services and webmail hosts generate Message-IDs with their own names; it does not show that the message is forged."),
  ("Message-ID de otro dominio",
   "El Message-ID se generó bajo %{message_id_domain}, no bajo el dominio del remitente %{from_domain}.",
   "Los clientes de correo, los servicios de envío y los proveedores de webmail generan Message-ID con su propio nombre; no indica que el mensaje sea falso."),
  ("Message-ID d'un autre domaine",
   "Le Message-ID a été généré sous %{message_id_domain}, et non sous le domaine de l'expéditeur %{from_domain}.",
   "Les clients de messagerie, services d'envoi et webmails génèrent des Message-ID à leur propre nom ; cela n'indique pas que le message est falsifié."))
f("DKIM_KEY_NOT_AVAILABLE",
  ("DKIM key not available",
   "No public key for %{name} was supplied, so the signature of %{d} (selector %{s}) could not be checked (offline analysis, no DNS query).",
   "It says nothing about the signature; supply the key that was valid at sending time to check it."),
  ("Clave DKIM no disponible",
   "No se suministró la clave pública de %{name}, por lo que no pudo comprobarse la firma de %{d} (selector %{s}) (análisis sin conexión, sin consulta DNS).",
   "No dice nada de la firma; suministre la clave vigente en el momento del envío para comprobarla."),
  ("Clé DKIM non disponible",
   "Aucune clé publique pour %{name} n'a été fournie, la signature de %{d} (sélecteur %{s}) n'a donc pas pu être vérifiée (analyse hors ligne, sans requête DNS).",
   "Cela ne dit rien de la signature ; fournissez la clé en vigueur lors de l'envoi pour la vérifier."))
f("PAYMENT_DETAILS_MENTIONED",
  ("Payment details mentioned",
   "The subject or text mentions payment details: %{terms}.",
   "Invoices and payment notices mention bank details all the time; it is a pointer for review, not a sign of fraud."),
  ("Se mencionan datos de pago",
   "El asunto o el texto mencionan datos de pago: %{terms}.",
   "Las facturas y los avisos de pago mencionan datos bancarios constantemente; es una indicación para revisar, no un signo de fraude."),
  ("Coordonnées de paiement mentionnées",
   "L'objet ou le texte mentionne des coordonnées de paiement : %{terms}.",
   "Factures et avis de paiement mentionnent sans cesse des coordonnées bancaires ; c'est un repère pour l'examen, pas un signe de fraude."))
f("DKIM_SIGNATURE_VALID",
  ("DKIM signature verifies",
   "The DKIM signature of %{d} (selector %{s}, %{a}) verifies with the key from %{key_source}: the signed header fields and the body are unchanged since signing.",
   "It shows only that whoever held the private key of %{d} signed this content; it does not show who wrote it, that the From address is truthful, or that unsigned header fields are original."),
  ("La firma DKIM se verifica",
   "La firma DKIM de %{d} (selector %{s}, %{a}) se verifica con la clave de %{key_source}: los campos de cabecera firmados y el cuerpo no han cambiado desde la firma.",
   "Solo indica que quien tenía la clave privada de %{d} firmó este contenido; no indica quién lo escribió, que el remitente sea veraz ni que las cabeceras no firmadas sean originales."),
  ("La signature DKIM se vérifie",
   "La signature DKIM de %{d} (sélecteur %{s}, %{a}) se vérifie avec la clé issue de %{key_source} : les en-têtes signés et le corps n'ont pas changé depuis la signature.",
   "Cela montre seulement que le détenteur de la clé privée de %{d} a signé ce contenu ; cela n'indique ni qui l'a rédigé, ni que l'expéditeur est véridique, ni que les en-têtes non signés sont d'origine."))
f("AUTH_RESULTS_RECORDED",
  ("Receiving server's checks recorded",
   "%{count} Authentication-Results header(s); the top one, written by %{authserv_id}, states: %{results}.",
   "These are claims written into the message by a server; anyone handling the file could have added or edited them, and they were not re-checked."),
  ("Comprobaciones del servidor receptor registradas",
   "%{count} cabecera(s) Authentication-Results; la superior, escrita por %{authserv_id}, declara: %{results}.",
   "Son afirmaciones escritas en el mensaje por un servidor; cualquiera que manejara el archivo pudo añadirlas o editarlas, y no se volvieron a comprobar."),
  ("Contrôles du serveur destinataire enregistrés",
   "%{count} en-tête(s) Authentication-Results ; le premier, écrit par %{authserv_id}, déclare : %{results}.",
   "Ce sont des affirmations écrites dans le message par un serveur ; toute personne ayant manipulé le fichier a pu les ajouter ou les modifier, et elles n'ont pas été revérifiées."))

L = {
    "DKIM_NEEDS_KEY_AT_SENDING_TIME": (
        "DKIM results depend on the public keys supplied: a check is only meaningful with the key that was valid when the message was sent. Keys are rotated, so a current key can fail a genuine message and a missing key leaves the signature unchecked.",
        "Los resultados DKIM dependen de las claves públicas suministradas: una comprobación solo tiene sentido con la clave vigente cuando se envió el mensaje. Las claves rotan, así que una clave actual puede fallar con un mensaje auténtico y una clave ausente deja la firma sin comprobar.",
        "Les résultats DKIM dépendent des clés publiques fournies : une vérification n'a de sens qu'avec la clé en vigueur lors de l'envoi. Les clés changent : une clé actuelle peut faire échouer un message authentique et une clé absente laisse la signature non vérifiée."),
    "MISSING_SIGNATURE_PROVES_NOTHING": (
        "A missing DKIM signature is common and proves nothing; a valid signature covers only the signed header fields and the body, not who wrote the message.",
        "La ausencia de firma DKIM es habitual y no demuestra nada; una firma válida cubre solo los campos de cabecera firmados y el cuerpo, no quién escribió el mensaje.",
        "L'absence de signature DKIM est courante et ne démontre rien ; une signature valide ne couvre que les en-têtes signés et le corps, pas l'auteur du message."),
    "MSG_MAY_LACK_TRANSPORT_HEADERS": (
        "Outlook .msg files do not keep the original message: the body is re-encoded (so DKIM cannot be checked) and the original header section is kept only when transport headers were stored.",
        "Los archivos .msg de Outlook no conservan el mensaje original: el cuerpo se recodifica (por lo que DKIM no puede comprobarse) y la sección de cabeceras original solo se conserva si se guardaron las cabeceras de transporte.",
        "Les fichiers .msg d'Outlook ne conservent pas le message d'origine : le corps est réencodé (DKIM ne peut donc pas être vérifié) et la section d'en-têtes d'origine n'est conservée que si les en-têtes de transport ont été enregistrés."),
    "BEC_HEURISTICS_FALSE_POSITIVES": (
        "Lookalike-domain, Reply-To, display-name and payment-wording checks are heuristics with false positives and false negatives; the organisational domain is estimated without the full Public Suffix List.",
        "Las comprobaciones de dominios parecidos, Reply-To, nombre visible y términos de pago son heurísticas con falsos positivos y falsos negativos; el dominio organizativo se estima sin la Public Suffix List completa.",
        "Les contrôles de domaines ressemblants, Reply-To, nom affiché et termes de paiement sont des heuristiques avec faux positifs et faux négatifs ; le domaine organisationnel est estimé sans la Public Suffix List complète."),
    "HEADERS_ARE_CLAIMS": (
        "Received, Date and Authentication-Results headers are text that servers and clients wrote; unsigned headers can be added or edited by anyone who handled the file.",
        "Las cabeceras Received, Date y Authentication-Results son texto escrito por servidores y clientes; las cabeceras no firmadas pueden añadirlas o editarlas quienes manejaron el archivo.",
        "Les en-têtes Received, Date et Authentication-Results sont du texte écrit par des serveurs et des clients ; les en-têtes non signés peuvent être ajoutés ou modifiés par quiconque a manipulé le fichier."),
    "MBOX_ESCAPING_AMBIGUOUS": (
        "In an mbox, body lines starting with \"From \" are escaped with '>'; un-escaping follows the selected variant (mboxrd by default) and cannot always restore the original line, which can affect DKIM body hashes.",
        "En un mbox, las líneas del cuerpo que empiezan por \"From \" se escapan con '>'; el desescapado sigue la variante elegida (mboxrd por defecto) y no siempre puede restaurar la línea original, lo que puede afectar al hash del cuerpo DKIM.",
        "Dans un mbox, les lignes du corps commençant par « From » sont échappées par « > » ; le déséchappement suit la variante choisie (mboxrd par défaut) et ne peut pas toujours restituer la ligne d'origine, ce qui peut affecter l'empreinte DKIM du corps."),
}

LABELS = {
    "mail_section": ("Email analysis", "Análisis del correo", "Analyse du message"),
    "mail_message_id": ("Message-ID", "Message-ID", "Message-ID"),
    "mail_from": ("From", "Remitente (From)", "Expéditeur (From)"),
    "mail_reply_to": ("Reply-To", "Responder a (Reply-To)", "Répondre à (Reply-To)"),
    "mail_return_path": ("Return-Path", "Return-Path", "Return-Path"),
    "mail_subject": ("Subject", "Asunto", "Objet"),
    "mail_date": ("Date header", "Cabecera Date", "En-tête Date"),
    "mail_hops": ("Received hops (first server = 1)", "Saltos Received (primer servidor = 1)", "Sauts Received (premier serveur = 1)"),
    "mail_hop": ("Hop", "Salto", "Saut"),
    "mail_hop_from": ("From host", "Desde", "Depuis"),
    "mail_hop_by": ("Received by", "Recibido por", "Reçu par"),
    "mail_hop_date": ("Date stamped", "Fecha registrada", "Date inscrite"),
    "mail_dkim": ("DKIM signatures (offline verification)", "Firmas DKIM (verificación sin conexión)", "Signatures DKIM (vérification hors ligne)"),
    "mail_dkim_domain": ("Domain (d=)", "Dominio (d=)", "Domaine (d=)"),
    "mail_dkim_selector": ("Selector (s=)", "Selector (s=)", "Sélecteur (s=)"),
    "mail_dkim_algorithm": ("Algorithm", "Algoritmo", "Algorithme"),
    "mail_dkim_result": ("Result", "Resultado", "Résultat"),
    "mail_key_source": ("Key source", "Origen de la clave", "Origine de la clé"),
    "mail_dkim_mode": ("DKIM mode / key file", "Modo DKIM / archivo de claves", "Mode DKIM / fichier de clés"),
    "mail_dkim_not_evaluated": ("DKIM not evaluated", "DKIM no evaluado", "DKIM non évalué"),
    "mail_arc": ("ARC chain", "Cadena ARC", "Chaîne ARC"),
    "mail_auth_results": ("Authentication-Results (as stated by the servers)", "Authentication-Results (según declaran los servidores)", "Authentication-Results (tels que déclarés par les serveurs)"),
    "mail_attachments": ("Attachments", "Adjuntos", "Pièces jointes"),
    "mail_attachment_name": ("Name", "Nombre", "Nom"),
    "mail_attachment_type": ("Type", "Tipo", "Type"),
    "mail_attachment_size": ("Size (bytes)", "Tamaño (bytes)", "Taille (octets)"),
    "mail_outputs": ("Files written by the analysis", "Archivos escritos por el análisis", "Fichiers écrits par l'analyse"),
    "mail_mbox_message": ("Message in mbox", "Mensaje en mbox", "Message dans le mbox"),
    "mail_mbox_messages": ("Messages in this mbox", "Mensajes en este mbox", "Messages dans ce mbox"),
    "mail_not_completed": ("The message analysis did not complete.", "El análisis del mensaje no terminó.", "L'analyse du message n'a pas abouti."),
    "mail_none": ("none", "ninguno", "aucun"),
}

METHOD = (
    "Each file was read once to compute its digests, then analysed as email: .eml as an RFC 5322 message, .msg through its MAPI properties, and each message of an mbox as an item of its own (each in a separate worker process with time and memory limits when worker isolation is on, as recorded in the audit log). The header section, Received hops and dates were read and compared; DKIM and ARC signatures were verified offline with the public keys the examiner supplied (no DNS query unless online mode was chosen); Authentication-Results were recorded as stated evidence; attachments were hashed; and BEC heuristics compared the addresses with the organisation's own domains. Every step and every file written is recorded in the hash-chained audit log.",
    "Cada archivo se leyó una vez para calcular sus huellas y después se analizó como correo: .eml como mensaje RFC 5322, .msg a través de sus propiedades MAPI y cada mensaje de un mbox como elemento propio (cada uno en un proceso de trabajo aparte con límites de tiempo y memoria cuando el aislamiento está activado, según consta en el registro de auditoría). Se leyeron y compararon la sección de cabeceras, los saltos Received y las fechas; las firmas DKIM y ARC se verificaron sin conexión con las claves públicas suministradas por el perito (sin consulta DNS salvo en modo en línea); las cabeceras Authentication-Results se registraron como declaraciones; se calculó el hash de los adjuntos; y heurísticas de BEC compararon las direcciones con los dominios propios de la organización. Cada paso y cada archivo escrito queda en el registro de auditoría encadenado por hash.",
    "Chaque fichier a été lu une fois pour calculer ses empreintes, puis analysé comme message : .eml comme message RFC 5322, .msg par ses propriétés MAPI et chaque message d'un mbox comme élément à part entière (chacun dans un processus de travail distinct avec limites de temps et de mémoire lorsque l’isolation est activée, comme le consigne le journal d’audit). La section d'en-têtes, les sauts Received et les dates ont été lus et comparés ; les signatures DKIM et ARC ont été vérifiées hors ligne avec les clés publiques fournies par l'expert (aucune requête DNS sauf en mode en ligne) ; les en-têtes Authentication-Results ont été consignés comme déclarations ; les pièces jointes ont été hachées ; et des heuristiques BEC ont comparé les adresses aux domaines propres de l'organisation. Chaque étape et chaque fichier écrit figurent dans le journal d'audit chaîné par hachage.",
)

LANGS = ("en", "es", "fr")


def main():
    for i, lang in enumerate(LANGS):
        p = ROOT / "i18n" / f"{lang}.json"
        cat = json.loads(p.read_text(encoding="utf-8"))
        for code, texts in F.items():
            t, s, d = texts[lang]
            cat["findings"][code] = {"title": t, "shows": s, "does_not_prove": d}
        for code, texts in L.items():
            cat["limitations"][code] = texts[i]
        for key, texts in LABELS.items():
            cat["labels"][key] = texts[i]
        cat["labels"]["method_text"] = METHOD[i]
        p.write_text(json.dumps(cat, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(F)} findings, {len(L)} limitations, {len(LABELS)} labels in {', '.join(LANGS)}")


if __name__ == "__main__":
    main()
