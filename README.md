# NEXURADATA

Site marketing et plateforme de lancement pour un laboratoire de recuperation de donnees et forensique numerique.

Le depot couvre maintenant:

- le site public
- le formulaire d'ouverture de dossier
- le portail client de suivi
- la console interne `/operations/`
- les Pages Functions Cloudflare pour l'intake, le suivi et les actions operateur
- la base D1 et la configuration `wrangler.jsonc`

## Structure utile

- `index.html`: page d'accueil publique
- `suivi-dossier-client-montreal.html`: portail client `noindex`
- `operations/index.html`: console interne a proteger via Cloudflare Access
- `assets/css/site.css`: styles partages
- `assets/js/site.js`: interactions publiques et console operateur
- `functions/api/intake.js`: ouverture de dossier
- `functions/api/status.js`: suivi client par numero + code
- `functions/api/ops/cases.js`: recherche et actions operateur
- `functions/_lib/`: logique partagee D1, acces et emails
- `migrations/0001_launch.sql`: schema D1
- `wrangler.jsonc`: configuration Pages/Functions a servir de source de verite
- `.dev.vars.example`: variables locales a copier vers `.dev.vars`

## Prerequis de lancement

1. Remplacer les IDs D1 placeholder dans `wrangler.jsonc`.
2. Creer un secret fort `ACCESS_CODE_SECRET`.
3. Configurer les alias `contact@`, `urgence@`, `dossiers@` dans Cloudflare Email Routing.
4. Verifier le domaine d'envoi dans Resend et fournir `RESEND_API_KEY`.
5. Proteger `/operations/*` et `/api/ops/*` avec Cloudflare Access.

Le runbook detaille est dans `LAUNCH-RUNBOOK.md`.

## Commandes

- `npm install`
- `npm run build`
- `npm run cf:whoami`
- `npm run cf:d1:migrate:local`
- `npm run cf:d1:migrate:remote`
- `npm run cf:dev`
- `npm run cf:check`
- `npm run cf:deploy`
- `npm run cf:deploy:staging`

`release-cloudflare/` est regenere a chaque build pour les assets statiques. Les `functions/` restent a la racine du projet pour Cloudflare Pages Functions.

## Cloudflare Pages

1. Connecter le repo GitHub a Cloudflare Pages.
2. Utiliser `.` comme root directory.
3. Utiliser `npm run build` comme build command.
4. Utiliser `release-cloudflare` comme build output directory.
5. Laisser `main` comme branche de production.
6. Utiliser la branche de lancement ou `staging` pour les previews.
7. Une fois `wrangler.jsonc` rempli avec les vrais bindings, traiter ce fichier comme source de verite pour la configuration.
