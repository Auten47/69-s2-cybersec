param(
    [string]$Container = "69-s2-app"
)

Write-Host "Patching Strapi..."

# 0. Email provider + plugin config + middlewares
docker exec $Container mkdir -p /opt/node_modules/@strapi/provider-email-smtp
docker cp "data-app\provider-email-smtp\package.json" "${Container}:/opt/node_modules/@strapi/provider-email-smtp/package.json"
docker cp "data-app\provider-email-smtp\index.js" "${Container}:/opt/node_modules/@strapi/provider-email-smtp/index.js"
docker cp "data-app\config\plugins.js" "${Container}:/opt/app/config/plugins.js"
docker cp "data-app\config\middlewares.js" "${Container}:/opt/app/config/middlewares.js"
docker exec $Container mkdir -p /opt/app/src/middlewares
docker cp "data-app\src\middlewares\rate-limit.js" "${Container}:/opt/app/src/middlewares/rate-limit.js"

# 1. User extension - create dirs first
docker exec $Container mkdir -p /opt/app/src/extensions/users-permissions/content-types/user
docker exec $Container mkdir -p /opt/app/scripts
docker exec $Container rm -f /opt/app/.env
docker cp "data-app\scripts\audit-verify.js" "${Container}:/opt/app/scripts/audit-verify.js"
docker cp "data-app\src\extensions\users-permissions\audit.js" "${Container}:/opt/app/src/extensions/users-permissions/audit.js"
docker cp "data-app\src\extensions\users-permissions\password.js" "${Container}:/opt/app/src/extensions/users-permissions/password.js"
docker cp "data-app\src\extensions\users-permissions\login-lock.js" "${Container}:/opt/app/src/extensions/users-permissions/login-lock.js"
docker cp "data-app\src\extensions\users-permissions\dbstore.js" "${Container}:/opt/app/src/extensions/users-permissions/dbstore.js"
docker cp "data-app\src\extensions\users-permissions\otp.js" "${Container}:/opt/app/src/extensions/users-permissions/otp.js"
docker cp "data-app\src\extensions\users-permissions\refresh-token.js" "${Container}:/opt/app/src/extensions/users-permissions/refresh-token.js"
docker cp "data-app\src\extensions\users-permissions\strapi-server.js" "${Container}:/opt/app/src/extensions/users-permissions/strapi-server.js"
docker cp "data-app\src\extensions\users-permissions\content-types\user\schema.json" "${Container}:/opt/app/src/extensions/users-permissions/content-types/user/schema.json"

# 2. Admin auth service
docker cp "data-app\patches\admin-auth-service.js" "${Container}:/opt/node_modules/@strapi/admin/server/services/auth.js"

# 3. Admin auth controller (MFA + renew limit + audits)
docker cp "data-app\patches\admin-auth-controller.js" "${Container}:/opt/node_modules/@strapi/admin/server/controllers/authentication.js"

# 4. Admin authenticated-user controller (updateMe: policy + audit + current-password)
docker cp "data-app\patches\admin-authenticated-user-controller.js" "${Container}:/opt/node_modules/@strapi/admin/server/controllers/authenticated-user.js"

# 5. Admin token service (jwtVersion embedding + short lifetime)
docker cp "data-app\patches\admin-token.js" "${Container}:/opt/node_modules/@strapi/admin/server/services/token.js"

# 6. Admin user service (bump jwtVersion on password change)
docker cp "data-app\patches\admin-user-service.js" "${Container}:/opt/node_modules/@strapi/admin/server/services/user.js"

# 7. Admin user content-type (jwtVersion + OTP fields)
docker cp "data-app\patches\admin-user-content-type.js" "${Container}:/opt/node_modules/@strapi/admin/server/content-types/User.js"

# 8. Admin strategy (reject stale jwtVersion)
docker cp "data-app\patches\admin-strategy.js" "${Container}:/opt/node_modules/@strapi/admin/server/strategies/admin.js"

# 9. Users-permissions strategy (reject stale jwtVersion)
docker cp "data-app\patches\up-strategy.js" "${Container}:/opt/node_modules/@strapi/plugin-users-permissions/server/strategies/users-permissions.js"

# 10. Users-permissions user controller (self-only updates + password policy)
docker cp "data-app\patches\up-user-controller.js" "${Container}:/opt/node_modules/@strapi/plugin-users-permissions/server/controllers/user.js"

# 11. Admin routes (add MFA endpoints)
docker cp "data-app\patches\admin-routes-authentication.js" "${Container}:/opt/node_modules/@strapi/admin/server/routes/authentication.js"

Write-Host "Restarting container..."
docker restart $Container

Write-Host "Waiting for Strapi to start (30s)..."
Start-Sleep -Seconds 30

Write-Host "`nAll patches applied!"