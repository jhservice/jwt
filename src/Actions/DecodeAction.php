<?php

declare(strict_types=1);

namespace JHService\JWT\Actions;

use JHService\JWT\Exceptions\Decode\DecodeException;
use JHService\JWT\Exceptions\Decode\HeaderDecodeException;
use JHService\JWT\Exceptions\Decode\PayloadDecodeException;
use JHService\JWT\Exceptions\Decode\SignatureDecodeException;
use JHService\JWT\Exceptions\JWTIsExpiredException;
use JHService\JWT\Traits\Functions;
use JHService\Singleton\Singleton;
use Throwable;

final class DecodeAction extends Singleton
{
    use Functions;

    /**
     * @throws DecodeException
     * @throws HeaderDecodeException
     * @throws PayloadDecodeException
     * @throws SignatureDecodeException
     * @throws JWTIsExpiredException
     */
    public function handle(string $jwt, string $signature_key = ''): array
    {
        try {
            $jwt = trim($jwt);
            if ($jwt === '') {
                throw new DecodeException('JWT Must Not Be Empty');
            }

            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                throw new DecodeException('JWT Structure Is Invalid');
            }

            $this->header_decode($parts[0]);

            $payload = $this->payload_decode($parts[1]);

            $this->signature_decode($parts[0], $parts[1], $parts[2], $signature_key);

            if ($payload['expiration_time'] <= $this->now()) {
                throw new JWTIsExpiredException('JWT Is Expired');
            }

            return $payload;
        } catch (DecodeException|HeaderDecodeException|PayloadDecodeException|SignatureDecodeException|JWTIsExpiredException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new DecodeException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }
}
