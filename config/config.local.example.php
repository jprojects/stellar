<?php
/**
 * Stellar · ejemplo de config/config.local.php (ese fichero no va a git: cópialo y rellénalo).
 * Las claves de Quasar están documentadas en config/config.php y en README.md; las de Stellar, en STELLAR.md.
 */
return [
    'app_name' => 'Stellar',
    'template' => 'stellar',          // templates/stellar: colores propios y el botón «Copia per a Claude»
    'debug' => false,
    'base_url' => 'https://stellar.example.com',

    'db' => ['name' => 'stellar', 'user' => 'stellar', 'pass' => '…'],

    // API: la necesita el MCP (tools/mcp.php). Cada uno crea su token en Perfil → API.
    'api' => ['enabled' => true],

    'stellar' => [
        // Carpetas del servidor que se pueden analizar como código (un objetivo de código fuera de aquí se rechaza)
        'code_roots' => ['/home/usuario/Projects'],
        // true = permite analizar webs de la red interna (IP privadas). Por defecto no, para evitar SSRF.
        'allow_private' => false,
        // Prudencia con las webs analizadas
        'max_requests' => 150,         // peticiones por análisis
        'delay_ms' => 150,             // pausa entre peticiones
        'timeout' => 15,               // segundos por petición
        // Vulnerabilidades conocidas de dependencias y librerías JS con OSV.dev (solo se envían nombres y versiones)
        'osv' => true,
        // Probar si el servidor acepta TLS 1.0/1.1
        'tls_legacy' => true,
    ],
];
