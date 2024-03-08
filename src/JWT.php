<?php

declare(strict_types=1);

namespace JHService\JWT;

use JHService\JWT\Actions\DecodeAction;
use JHService\JWT\Actions\EncodeAction;
use JHService\JWT\Exceptions\Decode\DecodeException;
use JHService\JWT\Exceptions\Decode\HeaderDecodeException;
use JHService\JWT\Exceptions\Decode\PayloadDecodeException;
use JHService\JWT\Exceptions\Decode\SignatureDecodeException;
use JHService\JWT\Exceptions\Encode\EncodeException;
use JHService\JWT\Exceptions\Encode\HeaderEncodeException;
use JHService\JWT\Exceptions\Encode\PayloadEncodeException;
use JHService\JWT\Exceptions\Encode\SignatureEncodeException;
use JHService\JWT\Exceptions\JWTIsExpiredException;
use JHService\Singleton\Singleton;

final class JWT extends Singleton
{
    /**
     * @throws HeaderEncodeException
     * @throws PayloadEncodeException
     * @throws SignatureEncodeException
     * @throws EncodeException
     */
    public function encode(string $subject, int $expires_in_seconds, array $custom_claims = [], string $signature_key = ''): string
    {
        return EncodeAction::instance()->handle($subject, $expires_in_seconds, $custom_claims, $signature_key);
    }

    /**
     * @throws DecodeException
     * @throws HeaderDecodeException
     * @throws PayloadDecodeException
     * @throws SignatureDecodeException
     * @throws JWTIsExpiredException
     */
    public function decode(string $jwt, string $signature_key = ''): array
    {
        return DecodeAction::instance()->handle($jwt, $signature_key);
    }
}
