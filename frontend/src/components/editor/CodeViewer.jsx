import React, { useEffect, useRef } from 'react';
import Editor, { useMonaco } from '@monaco-editor/react';

const CodeViewer = ({ code = '', line = 1, language = 'python' }) => {
  const editorRef = useRef(null);
  const monaco = useMonaco();
  const decorationsRef = useRef([]);

  // Monaco uses "cpp" for C/C++/Header files
  const monacoLang = language === 'c' ? 'cpp' : language;

  const handleEditorDidMount = (editor) => {
    editorRef.current = editor;
    revealAndHighlightLine();
  };

  const revealAndHighlightLine = () => {
    if (!editorRef.current || !monaco || !line) return;

    const editor = editorRef.current;

    // 1. Scroll line into center view and position cursor
    editor.revealLineInCenter(line);
    editor.setPosition({ lineNumber: line, column: 1 });

    // 2. Clear previous highlighted lines
    decorationsRef.current = editor.deltaDecorations(decorationsRef.current, []);

    // 3. Add new whole-line highlights (styled via CSS classes)
    decorationsRef.current = editor.deltaDecorations([], [
      {
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: 'monaco-line-highlight-danger',
          marginClassName: 'monaco-margin-highlight-danger'
        }
      }
    ]);
  };

  useEffect(() => {
    revealAndHighlightLine();
  }, [line, code, monaco]);

  const options = {
    readOnly: true,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    lineNumbers: 'on',
    fontSize: 13,
    fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
    renderLineHighlight: 'all',
    wordWrap: 'on',
    automaticLayout: true,
    cursorBlinking: 'smooth',
  };

  return (
    <div
      className="h-[400px] w-full border border-[var(--border-glow)] rounded-[10px] overflow-hidden shadow-inner"
      style={{ background: '#0a100d' }}
    >
      <Editor
        height="100%"
        language={monacoLang}
        theme="vs-dark"
        value={code}
        options={options}
        onMount={handleEditorDidMount}
      />
    </div>
  );
};

export default CodeViewer;
