# IBM Security Verify Connector — идеальный первый запуск

Источник: `ONBOARDING_FIRST_LAUNCH_STANDARD.md`. Целевой пользователь: IT-администратор
или security engineer, впервые открывающий приложение.

## 1. Credential type
API Client (OAuth2 Client Credentials): `tenant_hostname` (например
`mycompany.verify.ibm.com`) + `client_id` + `client_secret`.

## 2. Идеальный флоу (без ограничений SDK)
1. **Ссылка на точное место в консоли** — "Applications > On-Premises/API clients >
   Add API client", с указанием минимально нужных entitlements
   (Manage users/groups, Read applications, Read policies, Read events), чтобы
   пользователь не создавал клиент с избыточными правами вслепую.
2. **Явное объяснение отличия от Verify Access** — коротко в самой модалке:
   "Это подключение для облачной SaaS-версии Verify. Если вы используете
   on-premises IBM Security Verify Access (бывший ISAM), этот коннектор не
   подойдёт" — чтобы пользователь с другим продуктом не тратил время на
   создание клиента впустую.
3. **Проверка перед сохранением** — реальный обмен client_id/secret на токен
   через `/v1.0/endpoint/default/token` и один тестовый вызов (`GET /v2.0/Users?count=1`),
   чтобы подтвердить одновременно tenant hostname, client_id и client_secret.
4. **После успеха — tenant health snapshot** — отключённые пользователи,
   недавние неудачные попытки входа из Audit Events, чтобы сразу увидеть
   живые данные.
5. **Ошибки — конкретные, не generic 401/403** — если hostname введён без
   поддомена или с лишним протоколом, явно подсказать правильный формат
   (`mycompany.verify.ibm.com`, без `https://`), а не просто "unauthorized".
6. **Явное предупреждение перед delete_user** — необратимое удаление в SCIM
   (в отличие от soft-delete у Okta), поэтому двухшаговое подтверждение с
   явным текстом "нельзя отменить".
7. **MFA factor removal** — предупреждение, что удаление MFA-фактора у
   пользователя снижает его защиту, и требует, чтобы пользователь заново
   зарегистрировал MFA при следующем входе.

## 3. SCIM-специфика в UI
Так как пагинация у Users/Groups идёт через `startIndex`/`count`, а не
`offset`/`limit`, поисковое поле в списке должно явно объяснять формат
фильтра (например placeholder "userName sw \"jane\""), а не просто "search"
как у остальных коннекторов портфеля — иначе пользователь введёт свободный
текст, который SCIM-фильтр не примет.
