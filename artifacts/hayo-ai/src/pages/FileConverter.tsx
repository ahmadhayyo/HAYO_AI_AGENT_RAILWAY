/**
 * File Converter — محول الصيغ
 * Unified uploader backed by the real server conversion engine
 * (services/file-converter.ts, ~35 conversions, deterministic — no AI needed).
 * Upload any supported file → pick an output format → download the result.
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { Upload, ArrowRight, Loader2, FileText, X, Home } from "lucide-react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";

// Mirrors the backend getSupportedConversions() map; also fetched live on mount
// so it stays in sync if the server adds formats.
const FALLBACK_CONVERSIONS: Record<string, string[]> = {
  pdf: ["txt", "docx", "xlsx", "csv"],
  docx: ["txt", "html", "pdf", "xlsx", "csv", "md"],
  doc: ["txt", "pdf", "docx"],
  xlsx: ["csv", "json", "txt", "pdf", "docx", "html"],
  xls: ["csv", "xlsx", "json", "pdf", "docx"],
  csv: ["xlsx", "json", "pdf", "docx", "txt", "html"],
  json: ["csv", "xlsx", "txt", "pdf", "html"],
  txt: ["pdf", "docx", "html", "md"],
  md: ["html", "pdf", "docx", "txt"],
  html: ["txt", "pdf", "docx", "md"],
  png: ["pdf", "jpg"],
  jpg: ["pdf", "png"],
  jpeg: ["pdf", "png"],
  gif: ["pdf"],
  webp: ["pdf", "jpg"],
};

function extOf(name: string): string {
  return (name.split(".").pop() || "").toLowerCase();
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = () => reject(new Error("read error"));
    reader.readAsDataURL(file);
  });
}

export default function FileConverter() {
  const { t } = useTranslation();
  const { isAuthenticated } = useAuth();
  const [conversions, setConversions] = useState<Record<string, string[]>>(FALLBACK_CONVERSIONS);
  const [file, setFile] = useState<File | null>(null);
  const [target, setTarget] = useState<string>("");
  const [isConverting, setIsConverting] = useState(false);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Keep the format matrix in sync with the server (falls back to the constant).
  useEffect(() => {
    if (!isAuthenticated) return;
    fetch("/api/office/conversions", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => { if (data && typeof data === "object") setConversions(data); })
      .catch(() => { /* keep fallback */ });
  }, [isAuthenticated]);

  const sourceExt = file ? extOf(file.name) : "";
  const targets = sourceExt ? (conversions[sourceExt] || []) : [];
  const acceptAttr = Object.keys(conversions).map((e) => `.${e}`).join(",");

  const pickFile = useCallback((f: File | null) => {
    if (!f) return;
    setFile(f);
    const ext = extOf(f.name);
    const avail = conversions[ext] || [];
    setTarget(avail[0] || "");
    if (avail.length === 0) toast.error(t("converter.noTargets"));
  }, [conversions, t]);

  const handleConvert = async () => {
    if (!file || !target) return;
    setIsConverting(true);
    try {
      const fileData = await fileToBase64(file);
      const res = await fetch("/api/office/convert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ fileData, fileName: file.name, targetFormat: target }),
      });
      if (!res.ok) {
        let msg = t("converter.convertFailed");
        try { const j = await res.json(); if (j?.error) msg = j.error; } catch { /* non-json */ }
        toast.error(msg);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const base = file.name.includes(".") ? file.name.slice(0, file.name.lastIndexOf(".")) : file.name;
      a.href = url;
      a.download = `${base}.${target}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(t("converter.convertSuccess"));
    } catch (e: any) {
      toast.error(e?.message || t("converter.convertFailed"));
    } finally {
      setIsConverting(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>{t("account.loginRequired")}</CardTitle>
            <CardDescription>{t("converter.loginDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild className="w-full">
              <a href={getLoginUrl()}>{t("common.login")}</a>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-3xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Link href="/dashboard" className="text-muted-foreground hover:text-primary p-1.5 rounded-lg hover:bg-accent transition-colors">
            <Home className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl md:text-3xl font-bold font-heading">{t("converter.title")}</h1>
            <p className="text-muted-foreground text-sm mt-1">{t("converter.subtitle")}</p>
          </div>
        </div>

        {/* Upload zone */}
        <Card>
          <CardContent className="pt-6">
            <input
              ref={inputRef}
              type="file"
              accept={acceptAttr}
              className="hidden"
              onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
            />

            {!file ? (
              <button
                type="button"
                onClick={() => inputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => { e.preventDefault(); setDragging(false); pickFile(e.dataTransfer.files?.[0] ?? null); }}
                className={`w-full flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed py-12 px-4 transition-colors ${
                  dragging ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-accent/40"
                }`}
              >
                <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center">
                  <Upload className="w-7 h-7 text-primary" />
                </div>
                <span className="font-medium">{t("converter.dropZone")}</span>
                <span className="text-xs text-muted-foreground text-center max-w-md">{t("converter.supportedNote")}</span>
              </button>
            ) : (
              <div className="flex items-center gap-3 rounded-xl border border-border p-4">
                <div className="w-11 h-11 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
                  <FileText className="w-5 h-5 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-medium truncate">{file.name}</p>
                  <p className="text-xs text-muted-foreground">{(file.size / 1024).toFixed(0)} KB · {sourceExt.toUpperCase()}</p>
                </div>
                <button onClick={() => { setFile(null); setTarget(""); }} className="text-muted-foreground hover:text-foreground p-1.5 rounded-lg hover:bg-accent" title={t("converter.removeFile")}>
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Target format + convert */}
        {file && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("converter.selectTarget")}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {targets.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("converter.noTargets")}</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {targets.map((fmt) => (
                    <button
                      key={fmt}
                      onClick={() => setTarget(fmt)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm font-medium transition-colors ${
                        target === fmt
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
                      }`}
                    >
                      <span className="uppercase text-xs text-muted-foreground">{sourceExt}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                      <span className="uppercase">{fmt}</span>
                    </button>
                  ))}
                </div>
              )}

              <Button
                onClick={handleConvert}
                disabled={!target || isConverting}
                size="lg"
                className="w-full gap-2"
              >
                {isConverting ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4 rtl:rotate-180" />}
                {isConverting ? t("converter.converting") : t("converter.convert")}
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Tips */}
        <Card className="bg-primary/5 border-primary/20">
          <CardHeader>
            <CardTitle className="text-sm">💡 {t("converter.tips")}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p>✓ {t("converter.tip1")}</p>
            <p>✓ {t("converter.tip2")}</p>
            <p>✓ {t("converter.tip3")}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
