<?php
/**
 * shape10 victim tenant app, php_binary-reader variant (vhost C —
 * session.serialize_handler = php_binary). Same app code as vhost B; only
 * the ini differs (set by the lab per-vhost ini file, exactly like two
 * tenants on a shared host configuring different serialize handlers).
 */
require __DIR__ . '/../docroot_victim/victim.php';
