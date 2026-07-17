import React from 'react';
import { DiffEditor } from '@monaco-editor/react';

const FixDiffViewer = ({ original = '', modified = '', language = 'python' }) => {
  const monacoLang = language === 'c' ? 'cpp' : language;

  const options = {
    readOnly: true,
    originalEditable: false,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    lineNumbers: 'on',
    fontSize: 13,
    fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
    renderSideBySide: true,
    wordWrap: 'on',
    automaticLayout: true,
    ignoreTrimWhitespace: false,
  };

  return (
    <div
      className="h-[300px] w-full border border-[var(--border-glow)] rounded-[10px] overflow-hidden"
      style={{ background: '#0a100d' }}
    >
      <DiffEditor
        height="100%"
        language={monacoLang}
        theme="vs-dark"
        original={original}
        modified={modified}
        options={options}
      />
    </div>
  );
};

export default FixDiffViewer;
