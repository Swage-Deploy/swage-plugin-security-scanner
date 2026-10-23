<?php

namespace Swage\SecurityScanner\Scanning;

/**
 * What a scan read from one access log, starting at a byte offset.
 */
final readonly class ScannedFile
{
    public function __construct(
        public string $path,
        public int $inode,
        public int $start,
        public bool $isNew,
        public string $content,
    ) {}

    /**
     * The complete lines read. A line still being written is left for the next scan, and a log read for the first
     * time drops the partial line its read started in the middle of.
     */
    public function lines(): string
    {
        $complete = substr($this->content, 0, $this->consumed());

        if ($this->isNew && $this->start > 0) {
            $complete = (string) substr($complete, strpos($complete, "\n") === false ? strlen($complete) : strpos($complete, "\n") + 1);
        }

        return $complete;
    }

    /**
     * The offset the next scan reads this log from.
     */
    public function nextOffset(): int
    {
        return $this->start + $this->consumed();
    }

    /**
     * The site the log belongs to, from Swage's "{domain}-access.log" naming, or "nginx" for the server's own log.
     */
    public function source(): string
    {
        $name = basename($this->path);

        return str_ends_with($name, '-access.log') ? substr($name, 0, -strlen('-access.log')) : 'nginx';
    }

    /**
     * The bytes up to and including the last complete line. A read that filled its limit without one is a single
     * enormous line, which is skipped rather than read forever.
     */
    protected function consumed(): int
    {
        $lastNewline = strrpos($this->content, "\n");

        if ($lastNewline !== false) {
            return $lastNewline + 1;
        }

        return strlen($this->content) >= ScanScript::MAX_BYTES_PER_FILE ? strlen($this->content) : 0;
    }
}
