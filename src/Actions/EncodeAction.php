<?php

declare(strict_types=1);

namespace JHService\JWT\Actions;

use JHService\JWT\Exceptions\Encode\EncodeException;
use JHService\JWT\Exceptions\Encode\HeaderEncodeException;
use JHService\JWT\Exceptions\Encode\PayloadEncodeException;
use JHService\JWT\Exceptions\Encode\SignatureEncodeException;
use JHService\JWT\Traits\Functions;
use JHService\Singleton\Singleton;
use Throwable;

final class EncodeAction extends Singleton
{
    use Functions;

    /**
     * @throws HeaderEncodeException
     * @throws PayloadEncodeException
     * @throws SignatureEncodeException
     * @throws EncodeException
     */
    public function handle(string $subject, int $expires_in_seconds, array $custom_claims = [], string $signature_key = ''): string
    {
        try {
            $header_encode = $this->header_encode();

            $payload_encode = $this->payload_encode($subject, $expires_in_seconds, $custom_claims);

            $signature_encode = $this->signature_encode($header_encode, $payload_encode, $signature_key);

            return sprintf('%s.%s.%s', $header_encode, $payload_encode, $signature_encode);
        } catch (HeaderEncodeException|PayloadEncodeException|SignatureEncodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new EncodeException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }
}
