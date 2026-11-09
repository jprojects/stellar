<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/** Stellar · se ha llegado al máximo de peticiones del análisis: los controles que faltan se saltan. */
final class RequestLimitException extends \RuntimeException
{
}
