import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal as TerminalIcon,
  Play,
  Square,
  Copy,
  Check,
  RotateCcw,
  SlidersHorizontal,
  ShieldAlert,
  Download,
  Info,
  ChevronRight,
  ExternalLink,
  Search,
  Zap,
  BookOpen
} from 'lucide-react';

interface TerminalLine {
  id: string;
  type: 'command' | 'stdout' | 'stderr' | 'system';
  content: string;
  timestamp: string;
}

// ANSI Escape Code to Styled HTML Spans
function parseAnsi(text: string): React.ReactNode[] {
  // Regex to match ANSI escape sequences
  const ansiRegex = /\x1b\[([0-9;]*)m/g;
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  let currentClasses: string[] = [];

  let key = 0;
  while ((match = ansiRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      const segment = text.slice(lastIndex, match.index);
      if (segment) {
        parts.push(
          <span key={key++} className={currentClasses.join(' ')}>
            {segment}
          </span>
        );
      }
    }

    const codes = match[1].split(';').map(c => parseInt(c, 10) || 0);
    for (const code of codes) {
      if (code === 0) {
        currentClasses = [];
      } else if (code === 1) {
        currentClasses.push('font-bold');
      } else if (code === 2) {
        currentClasses.push('opacity-60');
      } else if (code === 31 || code === 91) {
        currentClasses.push('text-red-400');
      } else if (code === 32 || code === 92) {
        currentClasses.push('text-emerald-400');
      } else if (code === 33 || code === 93) {
        currentClasses.push('text-amber-400');
      } else if (code === 34 || code === 94) {
        currentClasses.push('text-blue-400');
      } else if (code === 35 || code === 95) {
        currentClasses.push('text-purple-400');
      } else if (code === 36 || code === 96) {
        currentClasses.push('text-cyan-400');
      } else if (code === 37 || code === 97) {
        currentClasses.push('text-zinc-100');
      } else if (code === 90) {
        currentClasses.push('text-zinc-500');
      }
    }

    lastIndex = ansiRegex.lastIndex;
  }

  if (lastIndex < text.length) {
    parts.push(
      <span key={key++} className={currentClasses.join(' ')}>
        {text.slice(lastIndex)}
      </span>
    );
  }

  return parts;
}

export default function App() {
  const [history, setHistory] = useState<TerminalLine[]>([
    {
      id: 'init-1',
      type: 'system',
      content: 'Anubis Security Scanner v2.5.2 Linux Engine initialized. Ready for vulnerability assessment.',
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [inputVal, setInputVal] = useState<string>('anubis -h');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [commandHistory, setCommandHistory] = useState<string[]>(['anubis -h']);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [copiedInstall, setCopiedInstall] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'terminal' | 'builder' | 'docs'>('terminal');

  // Builder states
  const [builderTarget, setBuilderTarget] = useState<string>('https://scanme.nmap.org');
  const [builderLevel, setBuilderLevel] = useState<number>(2);
  const [builderCrawl, setBuilderCrawl] = useState<boolean>(true);
  const [builderGhost, setBuilderGhost] = useState<boolean>(true);
  const [builderDeepScan, setBuilderDeepScan] = useState<boolean>(false);
  const [builderSilent, setBuilderSilent] = useState<boolean>(false);
  const [builderStrategy, setBuilderStrategy] = useState<string>('polymorphic');
  const [builderFormat, setBuilderFormat] = useState<string>('html+json');
  const [selectedModules, setSelectedModules] = useState<string[]>(['sqli', 'xss', 'headers', 'fingerprint']);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const currentAbortController = useRef<AbortController | null>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  useEffect(() => {
    // Run initial help automatically once on load
    executeCommand('anubis -h');
  }, []);

  const executeCommand = async (cmdToRun: string) => {
    const trimmed = cmdToRun.trim();
    if (!trimmed) return;

    if (trimmed === 'clear' || trimmed === 'cls') {
      setHistory([]);
      return;
    }

    // Add command to history list
    setCommandHistory(prev => [trimmed, ...prev.filter(p => p !== trimmed)]);
    setHistoryIndex(-1);

    const now = new Date().toLocaleTimeString();
    setHistory(prev => [
      ...prev,
      {
        id: `cmd-${Date.now()}`,
        type: 'command',
        content: trimmed,
        timestamp: now,
      },
    ]);

    setIsRunning(true);
    const controller = new AbortController();
    currentAbortController.current = controller;

    try {
      const response = await fetch('/api/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: trimmed }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errText = await response.text();
        setHistory(prev => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            type: 'stderr',
            content: `Execution failed (${response.status}): ${errText}`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
        setIsRunning(false);
        return;
      }

      const data = await response.json();
      if (data.stdout) {
        setHistory(prev => [
          ...prev,
          {
            id: `out-${Date.now()}`,
            type: 'stdout',
            content: data.stdout,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
      if (data.stderr) {
        setHistory(prev => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            type: 'stderr',
            content: data.stderr,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
      setHistory(prev => [
        ...prev,
        {
          id: `sys-${Date.now()}`,
          type: 'system',
          content: `[Process completed with exit code ${data.exitCode}]`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setHistory(prev => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            type: 'stderr',
            content: `Network or runtime error: ${err.message}`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      } else {
        setHistory(prev => [
          ...prev,
          {
            id: `sys-${Date.now()}`,
            type: 'system',
            content: '^C [Scan terminated by user]',
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
    } finally {
      setIsRunning(false);
      currentAbortController.current = null;
    }
  };

  const stopCurrentProcess = () => {
    if (currentAbortController.current) {
      currentAbortController.current.abort();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      executeCommand(inputVal);
      setInputVal('anubis ');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0 && historyIndex < commandHistory.length - 1) {
        const nextIdx = historyIndex + 1;
        setHistoryIndex(nextIdx);
        setInputVal(commandHistory[nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setInputVal(commandHistory[nextIdx]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setInputVal('anubis ');
      }
    } else if (e.ctrlKey && e.key === 'c') {
      stopCurrentProcess();
    } else if (e.ctrlKey && e.key === 'l') {
      e.preventDefault();
      setHistory([]);
    }
  };

  const copyInstallCmd = () => {
    navigator.clipboard.writeText('curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash');
    setCopiedInstall(true);
    setTimeout(() => setCopiedInstall(false), 2000);
  };

  // Compile builder command
  const buildCommandString = () => {
    const parts = ['anubis', '-t', builderTarget, '-l', String(builderLevel)];
    if (selectedModules.length > 0) {
      parts.push('-m', selectedModules.join(','));
    }
    if (builderCrawl) parts.push('--crawl');
    if (builderGhost) parts.push('--ghost');
    if (builderDeepScan) parts.push('--deep-scan');
    if (builderSilent) parts.push('-s');
    if (builderStrategy !== 'jitter') parts.push('--strategy', builderStrategy);
    if (builderFormat !== 'html+json') parts.push('-f', builderFormat);
    return parts.join(' ');
  };

  const runBuiltCommand = () => {
    const cmd = buildCommandString();
    setActiveTab('terminal');
    executeCommand(cmd);
  };

  const allAvailableModules = [
    { id: 'sqli', name: 'SQL Injection' },
    { id: 'xss', name: 'Cross-Site Scripting' },
    { id: 'lfi', name: 'Local File Inclusion' },
    { id: 'ssti', name: 'Server-Side Template Injection' },
    { id: 'openredirect', name: 'Open Redirect' },
    { id: 'sensitive', name: 'Sensitive Data & Env Leaks' },
    { id: 'headers', name: 'Security Headers Audit' },
    { id: 'fingerprint', name: 'Tech Stack Fingerprinting' },
    { id: 'ssl', name: 'TLS & Certificate Cipher Audit' },
    { id: 'portscan', name: 'Fast TCP Port Scanner' },
    { id: 'dns', name: 'DNS Records & Subdomain Recon' },
    { id: 'brute_force', name: 'Path & Auth Bruteforce' },
  ];

  const toggleModule = (modId: string) => {
    setSelectedModules(prev =>
      prev.includes(modId) ? prev.filter(m => m !== modId) : [...prev, modId]
    );
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f0] flex flex-col font-sans selection:bg-red-900 selection:text-white">
      {/* Top Header Bar */}
      <header id="anubis-header" className="border-b border-zinc-800 bg-[#0d1320] px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-30 shadow-md">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-red-950/40 border border-red-800/40 px-2.5 py-1 rounded">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            <span className="font-bold text-red-400 text-sm tracking-wider font-mono">ANUBIS</span>
            <span className="text-xs bg-red-500/20 text-red-300 font-mono px-1 rounded">v2.5.2</span>
          </div>
          <div className="hidden sm:flex items-center gap-2 text-xs text-zinc-400 font-mono">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Linux CLI Engine (Native Go)</span>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-1 bg-zinc-900/80 p-1 rounded-md border border-zinc-800 text-xs">
          <button
            id="tab-terminal-btn"
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
              activeTab === 'terminal'
                ? 'bg-zinc-800 text-white font-medium shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <TerminalIcon className="w-3.5 h-3.5 text-red-400" />
            <span>Interactive Terminal</span>
          </button>
          <button
            id="tab-builder-btn"
            onClick={() => setActiveTab('builder')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
              activeTab === 'builder'
                ? 'bg-zinc-800 text-white font-medium shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Command Builder</span>
          </button>
          <button
            id="tab-docs-btn"
            onClick={() => setActiveTab('docs')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
              activeTab === 'docs'
                ? 'bg-zinc-800 text-white font-medium shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5 text-amber-400" />
            <span>CLI Flags Guide</span>
          </button>
        </div>

        {/* Quick Install Linux Button */}
        <div className="flex items-center gap-2">
          <button
            id="btn-copy-install"
            onClick={copyInstallCmd}
            className="flex items-center gap-1.5 text-xs bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 px-3 py-1.5 rounded transition text-zinc-300"
            title="Copy 1-line Linux installation script"
          >
            {copiedInstall ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-mono">Copied install!</span>
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5 text-zinc-400" />
                <span>Install on Linux: <code className="text-red-300">curl | bash</code></span>
              </>
            )}
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col p-3 sm:p-4 max-w-7xl mx-auto w-full">
        {activeTab === 'terminal' && (
          <div className="flex-1 flex flex-col border border-zinc-800 rounded-lg bg-[#070b12] overflow-hidden shadow-2xl">
            {/* Terminal Window Title Bar */}
            <div className="bg-[#0f172a] border-b border-zinc-800/80 px-4 py-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block"></span>
                <span className="ml-2 text-xs font-mono text-zinc-400 flex items-center gap-1">
                  <TerminalIcon className="w-3.5 h-3.5 text-zinc-500" />
                  root@anubis-linux-box:~
                </span>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex items-center gap-1 overflow-x-auto text-[11px] font-mono">
                <button
                  id="quick-cmd-help"
                  onClick={() => executeCommand('anubis -h')}
                  disabled={isRunning}
                  className="px-2 py-1 bg-zinc-800/70 hover:bg-zinc-700 rounded text-zinc-300 border border-zinc-700/50 disabled:opacity-50"
                >
                  anubis -h
                </button>
                <button
                  id="quick-cmd-ver"
                  onClick={() => executeCommand('anubis --version')}
                  disabled={isRunning}
                  className="px-2 py-1 bg-zinc-800/70 hover:bg-zinc-700 rounded text-zinc-300 border border-zinc-700/50 disabled:opacity-50"
                >
                  --version
                </button>
                <button
                  id="quick-cmd-scan1"
                  onClick={() => executeCommand('anubis -t https://scanme.nmap.org -l 1')}
                  disabled={isRunning}
                  className="px-2 py-1 bg-zinc-800/70 hover:bg-zinc-700 rounded text-zinc-300 border border-zinc-700/50 disabled:opacity-50"
                >
                  Scan L1 (Passive)
                </button>
                <button
                  id="quick-cmd-scan2"
                  onClick={() => executeCommand('anubis -t https://scanme.nmap.org -l 2 --crawl --ghost')}
                  disabled={isRunning}
                  className="px-2 py-1 bg-zinc-800/70 hover:bg-zinc-700 rounded text-zinc-300 border border-zinc-700/50 disabled:opacity-50"
                >
                  Scan L2 (Ghost + Crawl)
                </button>
                <button
                  id="quick-cmd-clear"
                  onClick={() => setHistory([])}
                  className="px-2 py-1 bg-zinc-800/40 hover:bg-zinc-700 rounded text-zinc-400"
                  title="Clear Terminal (Ctrl+L)"
                >
                  <RotateCcw className="w-3 h-3 inline mr-1" />
                  Clear
                </button>
              </div>
            </div>

            {/* Terminal Body Screen */}
            <div
              id="terminal-screen"
              className="flex-1 p-4 overflow-y-auto font-mono text-sm leading-relaxed text-zinc-300 space-y-1 select-text min-h-[480px] max-h-[72vh]"
            >
              {history.map(line => {
                if (line.type === 'command') {
                  return (
                    <div key={line.id} className="flex items-start gap-2 pt-2 border-t border-zinc-800/40">
                      <span className="text-red-400 font-bold select-none">root@anubis:~#</span>
                      <span className="text-white font-semibold flex-1">{line.content}</span>
                      <span className="text-[10px] text-zinc-600 select-none">{line.timestamp}</span>
                    </div>
                  );
                }
                if (line.type === 'system') {
                  return (
                    <div key={line.id} className="text-zinc-500 text-xs py-0.5 italic">
                      {line.content}
                    </div>
                  );
                }
                if (line.type === 'stderr') {
                  return (
                    <pre key={line.id} className="text-red-400 whitespace-pre-wrap break-all py-0.5">
                      {parseAnsi(line.content)}
                    </pre>
                  );
                }
                return (
                  <pre key={line.id} className="text-zinc-200 whitespace-pre-wrap break-all py-0.5">
                    {parseAnsi(line.content)}
                  </pre>
                );
              })}

              {isRunning && (
                <div className="flex items-center gap-2 text-cyan-400 text-xs py-2 animate-pulse">
                  <Zap className="w-3.5 h-3.5" />
                  <span>Anubis process executing... Streaming live output</span>
                </div>
              )}

              <div ref={terminalEndRef} />
            </div>

            {/* Terminal Input Command Line */}
            <div className="bg-[#0b101b] border-t border-zinc-800 px-4 py-3 flex items-center gap-3">
              <span className="text-red-400 font-bold font-mono text-sm select-none shrink-0">
                root@anubis:~#
              </span>
              <input
                ref={inputRef}
                id="terminal-input"
                type="text"
                value={inputVal}
                onChange={e => setInputVal(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isRunning}
                placeholder="Type command (e.g. anubis -t https://example.com -l 2 --ghost) or 'clear'"
                className="flex-1 bg-transparent font-mono text-sm text-zinc-100 placeholder-zinc-600 outline-none border-none focus:ring-0"
                autoFocus
              />
              <div className="flex items-center gap-2">
                {isRunning ? (
                  <button
                    id="btn-stop-scan"
                    onClick={stopCurrentProcess}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/60 hover:bg-red-800 text-red-200 border border-red-700/60 text-xs font-mono rounded transition"
                  >
                    <Square className="w-3 h-3 fill-current" />
                    <span>Stop (SIGINT)</span>
                  </button>
                ) : (
                  <button
                    id="btn-exec-scan"
                    onClick={() => {
                      executeCommand(inputVal);
                      setInputVal('anubis ');
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-medium rounded transition shadow-sm"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>Execute</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Command Builder Tab */}
        {activeTab === 'builder' && (
          <div className="flex-1 border border-zinc-800 rounded-lg bg-[#070b12] p-5 space-y-6">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2 font-mono">
                <SlidersHorizontal className="w-5 h-5 text-cyan-400" />
                Anubis Visual Command Builder
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Configure your penetration testing flags and generate the exact Linux CLI command.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Target & Level */}
              <div className="space-y-4 bg-[#0d1424] p-4 rounded-lg border border-zinc-800">
                <div>
                  <label className="block text-xs font-mono text-zinc-300 font-semibold mb-1">
                    Target URL or Hostname (-t)
                  </label>
                  <input
                    id="builder-target-input"
                    type="text"
                    value={builderTarget}
                    onChange={e => setBuilderTarget(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-white font-mono focus:border-cyan-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-zinc-300 font-semibold mb-2">
                    Scan Level (-l)
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { l: 1, name: 'Level 1', desc: 'Passive Recon & Headers' },
                      { l: 2, name: 'Level 2', desc: 'Active Vulnerability Audit' },
                      { l: 3, name: 'Level 3', desc: 'Deep Exhaustive Scan' },
                    ].map(item => (
                      <button
                        key={item.l}
                        type="button"
                        onClick={() => setBuilderLevel(item.l)}
                        className={`p-2.5 rounded border text-left transition ${
                          builderLevel === item.l
                            ? 'bg-red-950/60 border-red-500 text-white'
                            : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:border-zinc-700'
                        }`}
                      >
                        <div className="font-bold text-xs font-mono">{item.name}</div>
                        <div className="text-[10px] text-zinc-400 mt-0.5">{item.desc}</div>
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono text-zinc-300 font-semibold mb-2">
                    Evasion & Anti-WAF Strategy (--strategy)
                  </label>
                  <select
                    value={builderStrategy}
                    onChange={e => setBuilderStrategy(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-white font-mono focus:border-cyan-500 outline-none"
                  >
                    <option value="jitter">Jitter (Randomized intervals)</option>
                    <option value="polymorphic">Polymorphic (Dynamic morphing signatures)</option>
                    <option value="linear">Linear (Constant throttled delay)</option>
                    <option value="exponential">Exponential (Backoff on throttle)</option>
                    <option value="fixed">Fixed (Predictable baseline timing)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-zinc-300 font-semibold mb-2">
                    Report Formats (-f)
                  </label>
                  <select
                    value={builderFormat}
                    onChange={e => setBuilderFormat(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-white font-mono focus:border-cyan-500 outline-none"
                  >
                    <option value="html+json">HTML + JSON (Comprehensive)</option>
                    <option value="html">HTML Standalone Executive Report</option>
                    <option value="json">Raw JSON (CI/CD Pipelines)</option>
                    <option value="csv">CSV (Spreadsheet Audits)</option>
                  </select>
                </div>
              </div>

              {/* Toggles & Modules */}
              <div className="space-y-4 bg-[#0d1424] p-4 rounded-lg border border-zinc-800">
                <div>
                  <label className="block text-xs font-mono text-zinc-300 font-semibold mb-2">
                    Engine Flags
                  </label>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <label className="flex items-center gap-2 p-2 bg-zinc-900/90 rounded border border-zinc-800 cursor-pointer hover:border-zinc-700">
                      <input
                        type="checkbox"
                        checked={builderCrawl}
                        onChange={e => setBuilderCrawl(e.target.checked)}
                        className="rounded border-zinc-700 text-red-600 focus:ring-0"
                      />
                      <span>--crawl (Target Discovery)</span>
                    </label>
                    <label className="flex items-center gap-2 p-2 bg-zinc-900/90 rounded border border-zinc-800 cursor-pointer hover:border-zinc-700">
                      <input
                        type="checkbox"
                        checked={builderGhost}
                        onChange={e => setBuilderGhost(e.target.checked)}
                        className="rounded border-zinc-700 text-red-600 focus:ring-0"
                      />
                      <span>--ghost (Stealth Mode)</span>
                    </label>
                    <label className="flex items-center gap-2 p-2 bg-zinc-900/90 rounded border border-zinc-800 cursor-pointer hover:border-zinc-700">
                      <input
                        type="checkbox"
                        checked={builderDeepScan}
                        onChange={e => setBuilderDeepScan(e.target.checked)}
                        className="rounded border-zinc-700 text-red-600 focus:ring-0"
                      />
                      <span>--deep-scan (Exhaustive)</span>
                    </label>
                    <label className="flex items-center gap-2 p-2 bg-zinc-900/90 rounded border border-zinc-800 cursor-pointer hover:border-zinc-700">
                      <input
                        type="checkbox"
                        checked={builderSilent}
                        onChange={e => setBuilderSilent(e.target.checked)}
                        className="rounded border-zinc-700 text-red-600 focus:ring-0"
                      />
                      <span>-s (Silent Pipe Output)</span>
                    </label>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono text-zinc-300 font-semibold mb-2">
                    Active Security Modules (-m)
                  </label>
                  <div className="grid grid-cols-2 gap-1.5 max-h-48 overflow-y-auto p-1 text-xs font-mono">
                    {allAvailableModules.map(mod => (
                      <button
                        key={mod.id}
                        type="button"
                        onClick={() => toggleModule(mod.id)}
                        className={`px-2 py-1.5 rounded text-left border transition flex items-center justify-between ${
                          selectedModules.includes(mod.id)
                            ? 'bg-cyan-950/40 border-cyan-500/60 text-cyan-200'
                            : 'bg-zinc-900/60 border-zinc-800 text-zinc-400 hover:border-zinc-700'
                        }`}
                      >
                        <span>{mod.id}</span>
                        <span className="text-[10px] text-zinc-500">{mod.name}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Generated Command Box */}
            <div className="bg-[#0b101b] border border-zinc-800 rounded-lg p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex-1 w-full overflow-x-auto">
                <span className="text-xs text-zinc-400 block font-mono mb-1">Generated CLI Command:</span>
                <code className="text-sm font-mono text-emerald-400 bg-zinc-900 px-3 py-1.5 rounded block border border-zinc-800">
                  {buildCommandString()}
                </code>
              </div>
              <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(buildCommandString());
                  }}
                  className="flex-1 sm:flex-initial px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-xs font-mono text-zinc-200 rounded border border-zinc-700 transition"
                >
                  <Copy className="w-3.5 h-3.5 inline mr-1" />
                  Copy
                </button>
                <button
                  type="button"
                  onClick={runBuiltCommand}
                  className="flex-1 sm:flex-initial px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-semibold rounded shadow-md transition flex items-center justify-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Send to Terminal
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Documentation Tab */}
        {activeTab === 'docs' && (
          <div className="flex-1 border border-zinc-800 rounded-lg bg-[#070b12] p-5 space-y-6 text-sm font-mono overflow-y-auto">
            <div className="border-b border-zinc-800 pb-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-amber-400" />
                Anubis Linux CLI Reference Manual
              </h2>
              <p className="text-xs text-zinc-400 mt-1 font-sans">
                Complete manual of commands, environment flags, and operational evasion parameters.
              </p>
            </div>

            <div className="space-y-4">
              <div className="bg-[#0e1626] p-4 rounded border border-zinc-800">
                <h3 className="text-cyan-400 font-bold mb-2">QUICK INSTALLATION (LINUX)</h3>
                <pre className="text-xs text-emerald-400 bg-black/50 p-2.5 rounded overflow-x-auto">
                  curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
                </pre>
                <p className="text-xs text-zinc-400 mt-2 font-sans">
                  The script auto-detects architecture (amd64 / arm64), verifies Go compiler availability, compiles the static binary without CGO dependencies, and installs it into <code className="text-zinc-200">/usr/local/bin/anubis</code>.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-[#0e1626] p-3.5 rounded border border-zinc-800">
                  <h4 className="text-zinc-200 font-bold text-xs mb-2">LEVELS (-l)</h4>
                  <ul className="text-xs space-y-1.5 text-zinc-400">
                    <li><strong className="text-white">-l 1:</strong> Passive reconnaissance, DNS enumeration, SSL/TLS audit, security headers check.</li>
                    <li><strong className="text-white">-l 2:</strong> Active vulnerability audit (SQLi, XSS, LFI, SSTI, open redirect, parameter pollution).</li>
                    <li><strong className="text-white">-l 3:</strong> Deep exhaustive fuzzing with polymorphic payloads and recursive crawler discovery.</li>
                  </ul>
                </div>

                <div className="bg-[#0e1626] p-3.5 rounded border border-zinc-800">
                  <h4 className="text-zinc-200 font-bold text-xs mb-2">EVASION & ANTI-WAF</h4>
                  <ul className="text-xs space-y-1.5 text-zinc-400">
                    <li><strong className="text-white">--ghost:</strong> Minimizes user-agent, headers and protocol footprints to evade signature WAFs.</li>
                    <li><strong className="text-white">--strategy polymorphic:</strong> Dynamically morphs delay algorithms and payload syntax.</li>
                    <li><strong className="text-white">--proxy socks5://127.0.0.1:9050:</strong> Routes all audit traffic through Tor or SOCKS5 proxies.</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer Info */}
      <footer className="border-t border-zinc-800/80 bg-[#0a0f1d] px-4 py-2 text-xs font-mono text-zinc-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span>Anubis v2.5.2</span>
          <span>•</span>
          <span className="text-zinc-400">Pure Static Go Core</span>
          <span>•</span>
          <span className="text-zinc-400">Interactive CLI Environment</span>
        </div>
        <div className="flex items-center gap-2 text-zinc-400">
          <span>Target Architecture: Linux / POSIX</span>
        </div>
      </footer>
    </div>
  );
}
