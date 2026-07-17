import React, { useState, useRef } from 'react';
import { Upload, FileUp, AlertTriangle } from 'lucide-react';
import Button from '../common/Button';
import Panel from '../common/Panel';

const FileDropzone = ({ onUpload, isUploading, allowedExtensions }) => {
  const [isDragActive, setIsDragActive] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setIsDragActive(true);
    } else if (e.type === 'dragleave') {
      setIsDragActive(false);
    }
  };

  const validateAndUpload = (file) => {
    setErrorMsg('');
    if (!file) return;

    const ext = file.name.split('.').pop().toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      setErrorMsg(`Unsupported file type. Allowed formats: ${allowedExtensions.join(', ')}`);
      return;
    }

    onUpload(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndUpload(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndUpload(e.target.files[0]);
    }
  };

  const triggerInputClick = () => {
    fileInputRef.current.click();
  };

  return (
    <div className="w-full">
      <Panel
        hoverable={!isUploading}
        className={`${isDragActive ? '!border-[var(--border-glow-active)]' : ''} ${
          isUploading ? 'pointer-events-none opacity-60' : ''
        }`}
      >
        <div
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          onClick={triggerInputClick}
          className="w-full min-h-[140px] flex flex-col items-center justify-center text-center cursor-pointer -my-1"
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={handleChange}
            accept={allowedExtensions.map((ext) => `.${ext}`).join(',')}
            disabled={isUploading}
          />

          {isUploading ? (
            <>
              <FileUp className="h-10 w-10 text-[var(--signal-green)] animate-bounce mb-3" />
              <p className="text-sm font-medium text-[var(--text-primary)]">
                Uploading codebase archives...
              </p>
              <p className="text-xs text-[var(--text-secondary)] mt-1">
                Extracting files and mapping workspace metadata
              </p>
            </>
          ) : (
            <>
              <Upload
                className={`h-10 w-10 mb-3 transition-colors ${
                  isDragActive
                    ? 'text-[var(--signal-green)]'
                    : 'text-[var(--text-secondary)]'
                }`}
              />
              <p className="text-sm font-semibold text-[var(--text-primary)]">
                Drag & drop source folder (ZIP) or single file here
              </p>
              <p className="text-xs text-[var(--text-secondary)] mt-1.5 mb-4">
                Supported languages: Python, JavaScript, TypeScript, Java, C/C++, PHP
              </p>
              <Button
                size="sm"
                variant="secondary"
                onClick={(e) => {
                  e.stopPropagation();
                  triggerInputClick();
                }}
              >
                Select File
              </Button>
            </>
          )}
        </div>
      </Panel>

      {errorMsg && (
        <div
          className="flex items-center gap-2 mt-3 p-3 rounded-lg text-xs border"
          style={{
            background: 'rgba(229,72,77,0.1)',
            borderColor: 'rgba(229,72,77,0.25)',
            color: 'var(--sev-critical)',
          }}
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {errorMsg}
        </div>
      )}
    </div>
  );
};

export default FileDropzone;
