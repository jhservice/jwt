<?php

declare(strict_types=1);

namespace JHService\JWT\Traits;

use JHService\JWT\Exceptions\Decode\HeaderDecodeException;
use JHService\JWT\Exceptions\Decode\PayloadDecodeException;
use JHService\JWT\Exceptions\Decode\SignatureDecodeException;
use JHService\JWT\Exceptions\Encode\HeaderEncodeException;
use JHService\JWT\Exceptions\Encode\PayloadEncodeException;
use JHService\JWT\Exceptions\Encode\SignatureEncodeException;
use Throwable;

trait Functions
{
    private function now(): int
    {
        $current_timezone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        $now = time();
        date_default_timezone_set($current_timezone);
        return $now;
    }

    /**
     * @throws HeaderEncodeException
     */
    private function header_encode(): string
    {
        try {
            $header = [
                'alg' => 'HS512',
                'typ' => 'JWT',
            ];
            return jhservice_base64_url_encode(
                json_encode($header, JSON_OBJECT_AS_ARRAY | JSON_BIGINT_AS_STRING | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        } catch (Throwable $throwable) {
            throw new HeaderEncodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws PayloadEncodeException
     */
    private function payload_encode(string $subject, int $expires_in_seconds, array $custom_claims): string
    {
        try {
            $subject = trim($subject);
            if ($subject === '') {
                throw new PayloadEncodeException('JWT Subject Must Not Be Empty');
            }

            if ($expires_in_seconds < 1) {
                throw new PayloadEncodeException('JWT Expires In Seconds Must Be Greater Than Zero');
            }

            $now = $this->now();

            $payload = array_merge($custom_claims, [
                'jti' => date('Ymd-His-', $now) . random_int(10000000, 99999999),
                'sub' => $subject,
                'iat' => $now,
                'exp' => $now + $expires_in_seconds,
            ]);

            return jhservice_base64_url_encode(
                json_encode($payload, JSON_OBJECT_AS_ARRAY | JSON_BIGINT_AS_STRING | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        } catch (PayloadEncodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new PayloadEncodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws SignatureEncodeException
     */
    private function signature_encode(string $header_encode, string $payload_encode, string $signature_key = ''): string
    {
        try {
            $signature_key = trim($signature_key);
            if ($signature_key === '') {
                $signature_key = '-01234567899876543210-01234567899876543210-01234567899876543210-';
            }
            $signature = hash_hmac('sha512', $header_encode . "." . $payload_encode, $signature_key, true);
            return jhservice_base64_url_encode($signature);
        } catch (Throwable $throwable) {
            throw new SignatureEncodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws HeaderDecodeException
     */
    private function header_decode(string $header_encode): void
    {
        try {
            $header_encode = trim($header_encode);
            if ($header_encode === '') {
                throw new HeaderDecodeException('JWT Header Must Not Be Empty');
            }

            if ($header_encode !== $this->header_encode()) {
                throw new HeaderDecodeException('JWT Header Is Invalid');
            }
        } catch (HeaderDecodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new HeaderDecodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws PayloadDecodeException
     */
    private function payload_decode(string $payload_encode): array
    {
        try {
            $payload_encode = trim($payload_encode);
            if ($payload_encode === '') {
                throw new PayloadDecodeException('JWT Payload Must Not Be Empty');
            }

            $payload_decode = json_decode(jhservice_base64_url_decode($payload_encode), true, 512, JSON_OBJECT_AS_ARRAY | JSON_BIGINT_AS_STRING | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($payload_decode === null) {
                throw new PayloadDecodeException('JWT Payload Structure Is Invalid');
            }

            // +++++++++++++ JWT ID +++++++++++++ \\

            if (array_key_exists('jti', $payload_decode) === false) {
                throw new PayloadDecodeException('JWT Id Is Not Found');
            }
            $jwt_id = trim($payload_decode['jti'] ?? '');
            if (preg_match('/^[0-9]{8}-[0-9]{6}-[0-9]{8}$/', $jwt_id) === false) {
                throw new PayloadDecodeException('JWT Id Structure Is Invalid');
            }
            unset($payload_decode['jti']);
            $payload_decode['jwt_id'] = $jwt_id;

            // +++++++++++++ Subject +++++++++++++ \\

            if (array_key_exists('sub', $payload_decode) === false) {
                throw new PayloadDecodeException('JWT Subject Is Not Found');
            }
            $subject = trim($payload_decode['sub'] ?? '');
            if ($subject === '') {
                throw new PayloadDecodeException('JWT Subject Must Not Be Empty');
            }
            unset($payload_decode['sub']);
            $payload_decode['subject'] = $subject;

            // +++++++++++++ Issued At +++++++++++++ \\

            if (array_key_exists('iat', $payload_decode) === false) {
                throw new PayloadDecodeException('JWT Issued At Is Not Found');
            }
            $issued_at = (int)($payload_decode['iat'] ?? 0);
            if ($issued_at < 1) {
                throw new PayloadDecodeException('JWT Issued At Must Be Greater Than Zero');
            }
            if ($issued_at > $this->now()) {
                throw new PayloadDecodeException('JWT Issued At Is Invalid');
            }
            unset($payload_decode['iat']);
            $payload_decode['issued_at'] = $issued_at;

            // +++++++++++++ Expiration Time +++++++++++++ \\

            if (array_key_exists('exp', $payload_decode) === false) {
                throw new PayloadDecodeException('JWT Expiration Time Is Not Found');
            }
            $expiration_time = (int)($payload_decode['exp'] ?? 0);
            if ($expiration_time < 1) {
                throw new PayloadDecodeException('JWT Expiration Time Must Be Greater Than Zero');
            }
            if ($expiration_time < $issued_at) {
                throw new PayloadDecodeException('JWT Expiration Time Is Invalid');
            }
            unset($payload_decode['exp']);
            $payload_decode['expiration_time'] = $expiration_time;

            return $payload_decode;
        } catch (PayloadDecodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new PayloadDecodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws SignatureDecodeException
     */
    private function signature_decode(string $header_encode, string $payload_encode, string $signature_encode, string $signature_key = ''): void
    {
        try {
            $signature_encode = trim($signature_encode);
            if ($signature_encode === '') {
                throw new SignatureDecodeException('JWT Signature Must Not Be Empty');
            }
            if ($signature_encode !== $this->signature_encode($header_encode, $payload_encode, $signature_key)) {
                throw new SignatureDecodeException('JWT Signature Is Invalid');
            }
        } catch (SignatureDecodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new SignatureDecodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }
}
