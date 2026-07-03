/**
 * Model Settings Page — Customizable AI Instructions per Model
 * Admin-only: Edit system prompts for each AI model
 * Uses tRPC backend for real persistence
 */
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { RotateCcw, Save, ChevronDown, ChevronUp, Brain, Info, Loader2, CheckCircle2, AlertCircle } from "lucide-react";
import { motion } from "framer-motion";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

interface ModelInstruction {
  modelId: string;
  name: string;
  icon: string;
  defaultInstruction: string;
  customInstruction?: string;
  activeInstruction: string;
  isCustomized: boolean;
}

function ModelCard({
  model,
  onSave,
  onReset,
  savingId,
}: {
  model: ModelInstruction;
  onSave: (modelId: string, instruction: string) => Promise<void>;
  onReset: (modelId: string) => Promise<void>;
  savingId: string | null;
}) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const [editValue, setEditValue] = useState(model.activeInstruction);
  const isSaving = savingId === model.modelId;
  const isModified = editValue !== model.activeInstruction;

  useEffect(() => {
    setEditValue(model.activeInstruction);
  }, [model.activeInstruction]);

  return (
    <div className={`bg-card/70 backdrop-blur-sm border rounded-xl overflow-hidden transition-all ${model.isCustomized ? "border-indigo-500/30" : "border-border/40"}`}>
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-accent/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <span className="text-2xl">{model.icon}</span>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-foreground">{model.name}</h3>
              {model.isCustomized && (
                <Badge variant="outline" className="text-xs border-indigo-500/50 text-indigo-400">
                  {t("modelSettings.custom")}
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
              {model.activeInstruction.substring(0, 80)}...
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {model.isCustomized && (
            <Button
              variant="ghost"
              size="sm"
              className="text-orange-400 hover:text-orange-300 text-xs"
              disabled={isSaving}
              onClick={e => { e.stopPropagation(); onReset(model.modelId); }}
            >
              <RotateCcw className="w-3 h-3 ml-1" />
              {t("modelSettings.reset")}
            </Button>
          )}
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          )}
        </div>
      </div>

      {expanded && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="border-t border-border/40"
        >
          <div className="p-4 space-y-3">
            {model.isCustomized && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20">
                <CheckCircle2 className="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-indigo-300">
                  {t("modelSettings.usesCustom")}
                </p>
              </div>
            )}

            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                {t("modelSettings.systemPrompt")}
              </label>
              <Textarea
                value={editValue}
                onChange={e => setEditValue(e.target.value)}
                className="min-h-[160px] text-sm font-mono resize-none bg-background/50 border-border/60 focus:border-indigo-500/50"
                placeholder={t("modelSettings.promptPlaceholder")}
                dir="rtl"
              />
              <div className="flex items-center justify-between mt-1">
                <p className="text-xs text-muted-foreground">
                  {t("modelSettings.charCount", { n: editValue.length })}
                </p>
                {isModified && (
                  <p className="text-xs text-amber-400">{t("modelSettings.unsaved")}</p>
                )}
              </div>
            </div>

            {model.isCustomized && (
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                  {t("modelSettings.defaultInstr")}
                </label>
                <div className="p-3 rounded-lg bg-background/50 border border-border/40 text-xs text-muted-foreground font-mono leading-relaxed max-h-24 overflow-y-auto" dir="rtl">
                  {model.defaultInstruction}
                </div>
              </div>
            )}

            <div className="flex gap-2 justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setEditValue(model.defaultInstruction)}
                className="text-xs"
                disabled={isSaving}
              >
                {t("modelSettings.restoreDefault")}
              </Button>
              <Button
                size="sm"
                onClick={() => onSave(model.modelId, editValue)}
                disabled={isSaving || !isModified}
                className="bg-indigo-600 hover:bg-indigo-700 text-white text-xs gap-1 min-w-[120px]"
              >
                {isSaving ? (
                  <><Loader2 className="w-3 h-3 animate-spin" />{t("modelSettings.saving")}</>
                ) : (
                  <><Save className="w-3 h-3" />{t("modelSettings.saveInstr")}</>
                )}
              </Button>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

export default function ModelSettings() {
  const { t } = useTranslation();
  const [savingId, setSavingId] = useState<string | null>(null);

  const { data: models, isLoading, error, refetch } = trpc.modelInstructions.getAll.useQuery(undefined, {
    retry: 2,
    staleTime: 30000,
  });

  const updateMutation = trpc.modelInstructions.update.useMutation({
    onSuccess: (_data, variables) => {
      toast.success(t("modelSettings.savedToast", { name: models?.find(m => m.modelId === variables.modelId)?.name || variables.modelId }));
      refetch();
    },
    onError: (err) => {
      toast.error(t("modelSettings.saveFailed", { msg: err.message }));
    },
    onSettled: () => {
      setSavingId(null);
    },
  });

  const resetMutation = trpc.modelInstructions.reset.useMutation({
    onSuccess: (_data, variables) => {
      toast.success(t("modelSettings.resetToast", { name: models?.find(m => m.modelId === variables.modelId)?.name || variables.modelId }));
      refetch();
    },
    onError: (err) => {
      toast.error(t("modelSettings.resetFailed", { msg: err.message }));
    },
    onSettled: () => {
      setSavingId(null);
    },
  });

  const handleSave = async (modelId: string, instruction: string) => {
    setSavingId(modelId);
    updateMutation.mutate({ modelId, instruction });
  };

  const handleReset = async (modelId: string) => {
    setSavingId(modelId);
    resetMutation.mutate({ modelId });
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/20 flex items-center justify-center">
              <Brain className="w-5 h-5 text-indigo-400" />
            </div>
            <div className="flex-1">
              <h1 className="font-heading text-2xl font-bold text-foreground">{t("modelSettings.title")}</h1>
              <p className="text-sm text-muted-foreground">{t("modelSettings.subtitle")}</p>
            </div>
            <LanguageSwitcher />
          </div>

          <div className="mt-4 p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/20">
            <p className="text-sm text-indigo-300 leading-relaxed">
              <strong>{t("modelSettings.howItWorks")}</strong> {t("modelSettings.howItWorksBody")}
              <br />
              <strong className="text-indigo-200">{t("modelSettings.storage")}</strong> {t("modelSettings.storageBody")}
            </p>
          </div>
        </div>

        {isLoading && (
          <div className="flex items-center justify-center py-12 gap-3">
            <Loader2 className="w-6 h-6 animate-spin text-indigo-400" />
            <span className="text-muted-foreground">{t("modelSettings.loading")}</span>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
            <AlertCircle className="w-5 h-5 shrink-0" />
            <div>
              <p className="font-medium">{t("modelSettings.loadFailed")}</p>
              <p className="text-xs mt-1 opacity-80">{error.message}</p>
            </div>
            <Button variant="outline" size="sm" onClick={() => refetch()} className="mr-auto text-xs">
              {t("modelSettings.retry")}
            </Button>
          </div>
        )}

        {models && (
          <div className="space-y-3">
            {models.map((model: any, i: number) => (
              <motion.div
                key={model.modelId}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07 }}
              >
                <ModelCard model={model} onSave={handleSave} onReset={handleReset} savingId={savingId} />
              </motion.div>
            ))}
          </div>
        )}

        <div className="mt-8 p-4 rounded-xl bg-background/50 border border-border/40">
          <div className="flex items-start gap-2">
            <Info className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-xs text-muted-foreground">
              {t("modelSettings.footer1")}
              {t("modelSettings.footer2")}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
