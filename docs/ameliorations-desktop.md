# NovaSentinel — analyse et améliorations du bureau

## Organisation du projet

- `novaguard/app.py` lance l’application Windows et l’icône de notification.
- `novaguard/ui/dashboard.py` fournit la console CustomTkinter ; `i18n.py` contient les traductions.
- `core/engine.py` coordonne les analyses, les paramètres, l’historique et les décisions de quarantaine.
- `core/heuristics.py` analyse les fichiers : contenu, structure PE, imports, entropie, signature et réputation locale selon les fonctionnalités activées.
- `core/realtime.py` surveille les dossiers avec Watchdog ; `process_guard.py` examine les lancements.
- `core/ransomware_guard.py` conserve les incidents, contrôle les fichiers leurres et conserve des instantanés limités.
- `core/quarantine.py`, `lockdown.py`, `post_alert.py` et `telemetry.py` assurent respectivement l’isolement, le confinement, l’enrichissement et le contrôle de santé.
- `admin_console/` et `premium_cloud/` sont des composants web distincts pour l’administration et les abonnements. Cette intervention porte sur l’application de bureau.

## Interface et confort

Le thème clair est le défaut. Le sélecteur **Mode sombre**, dans la barre supérieure, change l’apparence immédiatement et conserve la préférence. Les tableaux natifs suivent également le thème. La navigation défile sur les petites fenêtres ; les cartes et les commandes d’analyse ont été adaptées pour éviter les débordements.

Le tableau de bord propose directement une analyse rapide. Le centre d’analyse sépare le nombre de menaces confirmées des éléments à vérifier. Chaque élément présente son chemin complet ; les décisions manuelles utilisent ce chemin pour distinguer les fichiers portant le même nom. La sélection reste stable pendant une actualisation.

La fin d’une analyse n’ouvre plus de fenêtre bloquante. Les notifications de fin sont désactivées par défaut et peuvent être activées dans les paramètres ; elles sont envoyées lorsque la fenêtre est masquée. Les résultats restent accessibles dans l’application.

## Refonte inspirée de LevelUp

La palette reprend les fonds neutres, les surfaces blanches ou anthracite, les accents violets et les bordures légères de LevelUp. Les icônes sont dessinées localement et suivent le thème. Les composants restent natifs : cette refonte ne nécessite pas de navigateur intégré.

- La barre supérieure réunit le fil d’Ariane et le thème. La navigation principale donne accès à la vue d’ensemble, aux analyses, à la quarantaine et aux événements. Les outils spécialisés sont regroupés sous **Plus d’outils**.
- L’accueil affiche les préférences réellement activées, les éléments restant à examiner dans l’analyse courante, le nombre de fichiers isolés et les derniers événements. Il ne prétend pas mesurer l’état de sécurité global de Windows.
- Le centre d’analyse distingue les contrôles rapides, complets et ciblés. Un fichier peut être choisi directement ; une cible absente ou invalide produit un message dans la page. Une analyse en cours n’est pas relancée depuis le bouton de l’accueil.
- Chaque fichier à examiner occupe une seule ligne. La sélection révèle tous ses indices dans un panneau de détail. Les boutons de décision nécessitent une sélection. Le résumé de fin reste affiché après la remise à zéro des compteurs du moteur.
- L’activité propose une recherche et un filtre d’alertes, avec deux vues : événements et historique récent des fichiers analysés.
- La quarantaine présente le nom et le chemin des fichiers, sans exposer leur identifiant interne comme colonne principale. Restaurer ou supprimer un fichier demande une confirmation, puis affiche le résultat de l’opération dans la page.
- Les préférences sont regroupées par protection, confort et dossiers surveillés. Le bouton d’enregistrement reste accessible pendant le défilement. Les saisies non enregistrées sont conservées lors d’un changement de page ou de thème.
- Les pages longues défilent à la taille minimale ; les colonnes des tableaux gardent une largeur lisible et défilent horizontalement. Les raccourcis `Ctrl+1`, `Ctrl+2` et `Ctrl+,` ouvrent respectivement l’accueil, les analyses et les préférences.

L’interface est organisée dans `ui/workspace.py`, les icônes dans `ui/icons.py` et les couleurs dans `ui/theme.py`. Les aperçus utilisent un moteur en mémoire et des données de démonstration : [clair](previews/apercu-demo-clair.png), [sombre](previews/apercu-demo-sombre.png).

## Réduction des décisions injustifiées

Les indices corrélés sont regroupés et plafonnés : les imports individuels et leurs familles ne s’additionnent plus sans limite. Les capacités statiques seules, même nombreuses, restent au stade de vérification et ne déclenchent pas la quarantaine automatique. Les commandes suspectes corroborées et les empreintes explicitement malveillantes conservent leur traitement automatique.

Une entrée de réputation seulement « suspicious » n’est plus un verdict malveillant. Le nom du test EICAR dans un document n’est plus suffisant : sa signature complète est vérifiée. Un programme signé conserve la politique de prudence existante pour ses capacités statiques.

Le nom d’un outil d’administration, ou une option comme `-Encoding`, n’est plus assimilé à une commande malveillante. Une commande suspecte au lancement n’autorise pas à mettre en quarantaine son interpréteur légitime. Elle reste disponible comme indice pour l’examen du processus et le mode d’urgence.

Une rafale de modifications seule est conservée pour examen, même avec un score élevé. Watchdog ne fournit ni l’identité de l’auteur des écritures, ni une preuve de chiffrement : sauvegardes, synchronisations et exports peuvent produire les mêmes événements. Le confinement automatique reste déclenchable par une altération vérifiée d’un fichier leurre ; le mode d’urgence manuel reste disponible.

Les fichiers système nécessitant une décision ne provoquent plus de dialogue depuis la surveillance en arrière-plan. La vérification manuelle garde son parcours de confirmation.

## Fiabilité et ressources

- Les événements répétés d’un même chemin sont regroupés. Le cache utilise la taille et la date de modification à la nanoseconde, au lieu d’ignorer toutes les modifications pendant deux secondes.
- Un fichier qui change pendant son analyse est écarté du verdict ; la surveillance le remet dans la file. Une empreinte périmée ne permet pas de mettre en quarantaine une nouvelle version lors d’une décision manuelle.
- Les fichiers leurres sont contrôlés par leur contenu. Les suppressions et les renommages sont aussi examinés ; les événements de métadonnées seuls ne déclenchent pas le confinement.
- La surveillance des processus distingue les réutilisations d’un identifiant grâce à l’heure de création et purge les processus disparus. Les erreurs ordinaires d’accès à un processus sont isolées.
- Les exclusions comparent les limites réelles des dossiers, pour ne pas confondre un dossier avec un voisin partageant son préfixe.
- Les dossiers choisis sont conservés au rechargement des paramètres. Modifier ces dossiers renouvelle une surveillance déjà active.
- Les mises à jour d’historique et d’événements sont synchronisées. Les paramètres de type incorrect et les listes JSON de forme incorrecte disposent d’un repli.
- Les instantanés de récupération sont limités à 256 candidats par session et à 256 Mio dans le dossier de récupération ; les fichiers individuels restent limités à 25 Mio. Le contrôle des autorisations n’est plus relancé à chaque lecture de l’état.

## Vérification et limites

Lancer les tests avec :

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Les tests isolent les données de l’application dans des dossiers temporaires et ne modifient pas les autorisations du système. Les tests de l’interface utilisent un moteur en mémoire, sans surveillance ni appels réseau. Les captures de contrôle ont été examinées en clair, en sombre et à la taille minimale de fenêtre.

La suite compte 111 tests réussis après la refonte, notamment pour la navigation, les filtres, les décisions de quarantaine, la conservation des préférences et le détail des résultats. Un cas de virtualisation des chemins par Windows a aussi été corrigé pour que les fichiers d’état de NovaSentinel restent exclus avant l’accès disque.

Ces changements visent à réduire les décisions agressives injustifiées ; ils ne constituent pas une mesure du taux de faux positifs. Une évaluation quantitative demande un corpus représentatif de logiciels légitimes et de menaces, analysé dans un environnement isolé. La politique plus prudente peut laisser certains programmes malveillants au stade de vérification lorsque seuls leurs indices statiques sont visibles.

NovaSentinel reste une protection complémentaire en espace utilisateur. Les copies du coffre de récupération sont prises après réception d’événements : elles ne garantissent pas de contenir une version saine antérieure à l’attaque et ne remplacent pas des sauvegardes. Le contrôle des fichiers leurres ne couvre que la surveillance active de l’application.
