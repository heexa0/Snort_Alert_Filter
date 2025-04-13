# Snort_Alert_Filter
Guide étape par étape pour atténuer les faux positifs dans un SIEM :
1. Ajustement des règles :
  • Examinez les règles de détection existantes au sein du SIEM.
  • Ajustez la sensibilité des règles pour trouver un équilibre entre la détection des véritables menaces et la minimisation des faux positifs.
  • Affinez les seuils et les paramètres pour mieux les aligner avec le comportement normal du réseau de l'organisation.
2. Liste blanche :
 • Identifiez les activités ou entités bénignes connues qui déclenchent systématiquement des faux positifs.
#exemple : Dressez une liste des applications, adresses IP, utilisateurs et autres entités qui sont considérés comme sûrs et qui ne devraient pas déclencher d'alertes.
• Créez des listes blanches pour exclure ces activités ou entités du déclenchement d'alertes.
• Mettez régulièrement à jour et affinez les listes blanches en fonction de l'évolution des environnements réseau et des exigences de sécurité.
3. Priorisation des menaces inconnues
 • Les systèmes de détection (comme les IDS/IPS) se concentrent souvent sur les menaces nouvelles ou sophistiquées, car les attaques courantes (ex: scans réseau  basiques Nmap, malware connu) sont déjà bien couvertes par des signatures ou règles existantes.
•	L'objectif est de réduire le bruit en éliminant les alertes redondantes sur des menaces déjà maîtrisées.
