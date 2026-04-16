# Runbook Lancement NEXURADATA

## 1. Cloudflare Pages et D1

1. Connecter le repo a Cloudflare Pages si ce n'est pas deja fait.
2. Creer une base D1 nommee `nexuradata-launch`.
3. Recuperer son `database_id` et son `preview_database_id`.
4. Remplacer les UUID placeholder dans `wrangler.jsonc`.
5. Copier `.dev.vars.example` vers `.dev.vars` pour le dev local.
6. Appliquer le schema:
   - local: `npm run cf:d1:migrate:local`
   - distant: `npm run cf:d1:migrate:remote`

## 2. Emails

### Cloudflare Email Routing

Creer ces adresses et les faire suivre vers une seule inbox verifiee au lancement:

- `contact@nexuradata.ca`
- `urgence@nexuradata.ca`
- `dossiers@nexuradata.ca`

### Resend

1. Verifier le domaine `nexuradata.ca` dans Resend.
2. Creer une cle API transactionnelle.
3. Declarer dans Cloudflare Pages:
   - `RESEND_API_KEY` comme secret
   - `RESEND_FROM_EMAIL` comme variable, par exemple `NEXURADATA <dossiers@nexuradata.ca>`
   - `LAB_INBOX_EMAIL` comme variable cible de l'equipe
   - `ACCESS_CODE_SECRET` comme secret

## 2.1 Paiements Stripe

### Variables et secrets Stripe

Declarer dans Cloudflare Pages:

- `STRIPE_SECRET_KEY` comme secret
- `STRIPE_WEBHOOK_SECRET` comme secret

### Webhook Stripe

Configurer un endpoint Stripe vers:

- `https://nexuradata.ca/api/stripe-webhook`

Evenements minimum:

- `checkout.session.completed`
- `checkout.session.async_payment_succeeded`
- `checkout.session.async_payment_failed`
- `checkout.session.expired`

### Mode operatoire v1

- les paiements sont crees depuis `/operations/`
- types prevus: acompte, solde final, paiement ponctuel
- chaque lien de paiement Stripe est rattache a un `caseId`
- le webhook met a jour le statut du paiement dans D1 et l'historique du dossier

## 3. Protection de la console interne

Configurer Cloudflare Access sur:

- `/operations/*`
- `/api/ops/*`

Recommandation v1:

- autoriser seulement les adresses operateur explicites
- propager l'entete `Cf-Access-Authenticated-User-Email`
- declarer `OPS_ACCESS_ALLOWED_EMAILS` ou `OPS_ACCESS_ALLOWED_DOMAIN`

## 4. Verification fonctionnelle

### Intake

1. Ouvrir `index.html`.
2. Soumettre un dossier test.
3. Verifier:
   - creation du `caseId`
   - insertion D1
   - notification interne
   - email client avec numero + code

### Portail client

1. Ouvrir `suivi-dossier-client-montreal.html`.
2. Utiliser le `caseId` et le code recus.
3. Verifier l'affichage du statut, de la prochaine etape et de la timeline visible.

### Console interne

1. Ouvrir `/operations/` depuis une session Access autorisee.
2. Rechercher le dossier.
3. Modifier statut, prochaine etape et resume.
4. Tester:
   - enregistrement
   - envoi de mise a jour client
   - renvoi du code
   - regeneration du code

## 5. Release

1. Travailler sur une branche de lancement.
2. Ouvrir une PR GitHub vers `main`.
3. Valider la preview Cloudflare.
4. Fusionner sur `main`.
5. Verifier en prod:
   - `https://nexuradata.ca/`
   - `https://www.nexuradata.ca/`
   - `https://nexuradata.ca/.well-known/security.txt`
   - `https://nexuradata.ca/suivi-dossier-client-montreal.html`

## 6. Variables et secrets attendus

Variables:

- `PUBLIC_SITE_ORIGIN`
- `LAB_INBOX_EMAIL`
- `OPS_ACCESS_ALLOWED_EMAILS` ou `OPS_ACCESS_ALLOWED_DOMAIN`
- `RESEND_FROM_EMAIL`

Secrets:

- `RESEND_API_KEY`
- `ACCESS_CODE_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
