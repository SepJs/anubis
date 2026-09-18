import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { spawn, execFile } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();

  let port = 3000;
  const portArgIndex = process.argv.indexOf('--port');
  if (portArgIndex !== -1 && process.argv[portArgIndex + 1]) {
    port = parseInt(process.argv[portArgIndex + 1], 10);
  } else if (process.env.PORT) {
    port = parseInt(process.env.PORT, 10);
  }

  app.use(express.json());

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    const binaryExists = fs.existsSync(path.join(__dirname, 'anubis'));
    res.json({
      status: 'ok',
      tool: 'anubis',
      version: '2.5.2',
      binaryExists,
      platform: process.platform,
      arch: process.arch,
    });
  });

  // Execute anubis CLI command
  app.post('/api/exec', (req: Request, res: Response) => {
    const { command, args: customArgs, stream } = req.body;
    let finalArgs: string[] = [];

    if (Array.isArray(customArgs)) {
      finalArgs = customArgs;
    } else if (typeof command === 'string') {
      const trimmed = command.trim();
      if (trimmed.startsWith('anubis ')) {
        finalArgs = trimmed.slice(7).trim().split(/\s+/).filter(Boolean);
      } else if (trimmed === 'anubis') {
        finalArgs = [];
      } else {
        finalArgs = trimmed.split(/\s+/).filter(Boolean);
      }
    }

    const binaryPath = path.join(__dirname, 'anubis');
    if (!fs.existsSync(binaryPath)) {
      res.status(500).json({
        error: 'Anubis binary not found. Build it with `go build -o anubis ./cmd/anubis`',
      });
      return;
    }

    // Default: fast & reliable JSON response
    if (!stream) {
      execFile(
        binaryPath,
        finalArgs,
        {
          cwd: __dirname,
          timeout: 180000,
          maxBuffer: 10 * 1024 * 1024,
          env: {
            ...process.env,
            TERM: 'xterm-256color',
            FORCE_COLOR: '1',
          },
        },
        (err, stdout, stderr) => {
          res.json({
            args: finalArgs,
            stdout: stdout || '',
            stderr: stderr || '',
            exitCode: err ? (err as any).code ?? 1 : 0,
          });
        }
      );
      return;
    }

    // Optional SSE streaming
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    const sendEvent = (event: string, data: unknown) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      if (typeof (res as any).flush === 'function') {
        (res as any).flush();
      }
    };

    sendEvent('start', { args: finalArgs, time: new Date().toISOString() });

    const proc = spawn(binaryPath, finalArgs, {
      cwd: __dirname,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        TERM: 'xterm-256color',
        FORCE_COLOR: '1',
      },
    });

    proc.stdout.on('data', (chunk: Buffer) => {
      sendEvent('stdout', { text: chunk.toString('utf-8') });
    });

    proc.stderr.on('data', (chunk: Buffer) => {
      sendEvent('stderr', { text: chunk.toString('utf-8') });
    });

    proc.on('close', (code: number | null) => {
      sendEvent('exit', { exitCode: code ?? 0 });
      res.end();
    });

    req.on('close', () => {
      if (!proc.killed) {
        proc.kill('SIGTERM');
      }
    });
  });

  // In development, hook Vite's middleware
  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`[Anubis Dev Server] Listening on http://0.0.0.0:${port}`);
  });
}

startServer().catch((err) => {
  console.error('[Anubis Dev Server] Fatal Error:', err);
  process.exit(1);
});
