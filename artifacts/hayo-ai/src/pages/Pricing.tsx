import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { Check, X, Zap, Crown, Rocket, Building2, ArrowRight, Shield, Star } from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { toast } from "sonner";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;

const PLANS = [
  {
    name: "free", displayName: "تجريبي", nameKey: "plan_free_name", tagKey: "plan_free_tag", icon: Zap, emoji: "🆓",
    gradient: "from-slate-500 to-slate-600", border: "border-slate-500/30",
    priceMonthly: 0, priceYearly: 0,
    tagline: "تجربة مجانية — 3 أيام",
    limits: {
      dailyCredits: 20, monthlyCredits: 60,
      models: ["Haiku"],
      pipelines: 1, battles: 1,
      upload: "5 MB", studies: 1, office: 2, ea: 0, trading: 0,
      sandbox: false, webSearch: false, imageGen: false, fileCreation: false, priority: false,
    },
  },
  {
    name: "starter", displayName: "المبتدئ", nameKey: "plan_starter_name", tagKey: "plan_starter_tag", icon: Crown, emoji: "⭐",
    gradient: "from-indigo-500 to-purple-600", border: "border-indigo-500/30",
    priceMonthly: 12, priceYearly: 120,
    tagline: "للاستخدام الشخصي والطلاب",
    popular: false,
    limits: {
      dailyCredits: 50, monthlyCredits: 700,
      models: ["Haiku", "Sonnet"],
      pipelines: 5, battles: 5,
      upload: "20 MB", studies: 20, office: "∞", ea: 0, trading: 0,
      sandbox: false, webSearch: true, imageGen: false, fileCreation: true, priority: false,
    },
  },
  {
    name: "pro", displayName: "الاحترافي", nameKey: "plan_pro_name", tagKey: "plan_pro_tag", icon: Rocket, emoji: "🚀",
    gradient: "from-amber-500 to-orange-600", border: "border-amber-500/30",
    priceMonthly: 39, priceYearly: 390,
    tagline: "للمحترفين — الهندسة العكسية ومنشئ التطبيقات",
    popular: true,
    limits: {
      dailyCredits: 150, monthlyCredits: 2500,
      models: ["Haiku", "Sonnet", "Opus"],
      pipelines: 40, battles: 40,
      upload: "75 MB", studies: "∞", office: "∞", ea: 40, trading: 0,
      sandbox: true, webSearch: true, imageGen: true, fileCreation: true, priority: false,
    },
  },
  {
    name: "business", displayName: "الأعمال", nameKey: "plan_business_name", tagKey: "plan_business_tag", icon: Building2, emoji: "🏢",
    gradient: "from-violet-600 to-fuchsia-600", border: "border-violet-500/30",
    priceMonthly: 99, priceYearly: 990,
    tagline: "للشركات — تداول حقيقي و OSINT ودعم أولوية",
    limits: {
      dailyCredits: 400, monthlyCredits: 7000,
      models: ["Haiku", "Sonnet", "Opus"],
      pipelines: 200, battles: "∞",
      upload: "200 MB", studies: "∞", office: "∞", ea: "∞", trading: "∞",
      sandbox: true, webSearch: true, imageGen: true, fileCreation: true, priority: true,
    },
  },
];

const FEATURES = [
  { labelKey: "f_dailyCredits", key: "dailyCredits" },
  { labelKey: "f_monthlyCredits", key: "monthlyCredits" },
  { labelKey: "f_models", key: "models", isArray: true },
  { labelKey: "f_pipelines", key: "pipelines" },
  { labelKey: "f_battles", key: "battles" },
  { labelKey: "f_upload", key: "upload" },
  { labelKey: "f_studies", key: "studies" },
  { labelKey: "f_office", key: "office" },
  { labelKey: "f_ea", key: "ea" },
  { labelKey: "f_trading", key: "trading" },
  { labelKey: "f_webSearch", key: "webSearch", isBool: true },
  { labelKey: "f_imageGen", key: "imageGen", isBool: true },
  { labelKey: "f_fileCreation", key: "fileCreation", isBool: true },
  { labelKey: "f_sandbox", key: "sandbox", isBool: true },
  { labelKey: "f_priority", key: "priority", isBool: true },
];

export default function Pricing() {
  const { t, i18n } = useTranslation();
  const { isAuthenticated } = useAuth();
  const { data: usageData } = trpc.usage.subscription.useQuery(undefined, { enabled: isAuthenticated });
  const [billing, setBilling] = useState<"monthly" | "yearly">("monthly");

  const currentPlan = usageData?.plan?.name || "free";

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white" dir={i18n.dir()}>
      {/* Header */}
      <header className="border-b border-white/5 bg-[#0a0a0f]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-9 h-9 rounded-lg" />
            <span className="text-lg font-bold">HAYO AI</span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/chat"><Button variant="ghost" size="sm">{t("nav.chat")}</Button></Link>
            {isAuthenticated ? (
              <Link href="/account"><Button size="sm" className="bg-gradient-to-r from-indigo-500 to-purple-600">{t("nav.account")}</Button></Link>
            ) : (
              <a href={getLoginUrl()}><Button size="sm" className="bg-gradient-to-r from-indigo-500 to-purple-600">{t("common.login")}</Button></a>
            )}
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="py-16 text-center">
        <div className="max-w-4xl mx-auto px-6">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-indigo-500/10 border border-indigo-500/20 mb-6">
            <Shield className="w-4 h-4 text-indigo-400" />
            <span className="text-sm text-indigo-300">{t("pricing.badge")}</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            {t("pricing.heroTitle")} <span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">{t("pricing.heroTitleHl")}</span>
          </h1>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto mb-8">
            {t("pricing.heroDesc")}
          </p>

          {/* Billing Toggle */}
          <div className="inline-flex items-center bg-white/5 rounded-xl p-1 border border-white/10">
            <button onClick={() => setBilling("monthly")} className={`px-6 py-2.5 rounded-lg text-sm font-medium transition-all ${billing === "monthly" ? "bg-indigo-500 text-white shadow" : "text-gray-400"}`}>
              {t("pricing.billMonthly")}
            </button>
            <button onClick={() => setBilling("yearly")} className={`px-6 py-2.5 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${billing === "yearly" ? "bg-indigo-500 text-white shadow" : "text-gray-400"}`}>
              {t("pricing.billYearly")} <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full">{t("pricing.save20")}</span>
            </button>
          </div>
        </div>
      </section>

      {/* Plans Grid */}
      <section className="pb-12">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
            {PLANS.map(plan => {
              const Icon = plan.icon;
              const isCurrent = currentPlan === plan.name;
              const price = billing === "yearly" ? plan.priceYearly : plan.priceMonthly;
              const monthlyEquiv = billing === "yearly" && plan.priceYearly > 0 ? (plan.priceYearly / 12).toFixed(2) : null;

              return (
                <div key={plan.name} className={`relative rounded-2xl border p-6 flex flex-col ${plan.popular ? "border-amber-500/50 bg-amber-500/5 ring-1 ring-amber-500/20" : "border-white/10 bg-white/[0.02]"}`}>
                  {plan.popular && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-gradient-to-r from-amber-500 to-orange-500 text-white text-xs font-bold px-4 py-1 rounded-full flex items-center gap-1">
                      <Star className="w-3 h-3" /> {t("pricing.popular")}
                    </div>
                  )}
                  {isCurrent && (
                    <div className="absolute -top-3 right-4 bg-emerald-500 text-white text-xs font-bold px-3 py-1 rounded-full">{t("pricing.currentPlan")}</div>
                  )}

                  <div className="flex items-center gap-3 mb-4">
                    <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${plan.gradient} flex items-center justify-center`}>
                      <Icon className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">{t(`pricing.${plan.nameKey}`)}</h3>
                      <p className="text-xs text-gray-400">{t(`pricing.${plan.tagKey}`)}</p>
                    </div>
                  </div>

                  <div className="mb-6">
                    <div className="flex items-baseline gap-1">
                      <span className="text-3xl font-bold">${price === 0 ? "0" : billing === "yearly" ? monthlyEquiv : price.toFixed(2)}</span>
                      {price > 0 && <span className="text-sm text-gray-400">{t("pricing.perMonth")}</span>}
                    </div>
                    {billing === "yearly" && price > 0 && (
                      <p className="text-xs text-emerald-400 mt-1">{t("pricing.perYearSave", { yearly: plan.priceYearly.toFixed(2), save: (plan.priceMonthly * 12 - plan.priceYearly).toFixed(0) })}</p>
                    )}
                    {price === 0 && <p className="text-xs text-amber-400 mt-1">{t("pricing.freeOnce")}</p>}
                  </div>

                  {/* Key Limits */}
                  <div className="space-y-2 flex-1 mb-6">
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{t("pricing.creditsLine", { daily: plan.limits.dailyCredits, monthly: plan.limits.monthlyCredits })}</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{t("pricing.modelsLabel", { models: plan.limits.models.join(" + ") })}</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{t("pricing.pipelinesUnit", { n: plan.limits.pipelines })}</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{t("pricing.battlesUnit", { n: plan.limits.battles })}</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{t("pricing.uploadUpTo", { size: plan.limits.upload })}</span></div>
                    {plan.limits.webSearch ? (
                      <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> {t("pricing.webSearch")}</div>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-gray-500"><X className="w-4 h-4 shrink-0" /> {t("pricing.webSearch")}</div>
                    )}
                    {plan.limits.priority && (
                      <div className="flex items-center gap-2 text-sm text-amber-400"><Crown className="w-4 h-4 shrink-0" /> {t("pricing.prioritySupport")}</div>
                    )}
                  </div>

                  {/* CTA */}
                  {plan.name === "free" ? (
                    <Button variant="outline" className="w-full" disabled={isCurrent}>
                      {isCurrent ? t("pricing.currentPlan") : t("pricing.startFree")}
                    </Button>
                  ) : (
                    <Link href={`/payment?plan=${plan.name}&billing=${billing}`}>
                      <Button className={`w-full gap-2 bg-gradient-to-r ${plan.gradient}`}>
                        {isCurrent ? t("pricing.currentPlan") : <><span>{t("pricing.subscribeNow")}</span> <ArrowRight className="w-4 h-4" /></>}
                      </Button>
                    </Link>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Feature Comparison Table */}
      <section className="pb-20">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="text-2xl font-bold text-center mb-8">{t("pricing.compareTitle")}</h2>
          <div className="overflow-x-auto rounded-2xl border border-white/10">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-white/5">
                  <th className="text-start px-6 py-4 font-medium text-gray-400">{t("pricing.featureCol")}</th>
                  {PLANS.map(p => (
                    <th key={p.name} className="px-4 py-4 text-center font-bold">{p.emoji} {t(`pricing.${p.nameKey}`)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {FEATURES.map((f, i) => (
                  <tr key={f.key} className={i % 2 === 0 ? "bg-white/[0.02]" : ""}>
                    <td className="px-6 py-3 text-gray-300 font-medium">{t(`pricing.${f.labelKey}`)}</td>
                    {PLANS.map(p => {
                      const val = (p.limits as any)[f.key];
                      return (
                        <td key={p.name} className="px-4 py-3 text-center">
                          {f.isBool ? (
                            val ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-gray-600 mx-auto" />
                          ) : f.isArray ? (
                            <span className="text-xs">{val.join(", ")}</span>
                          ) : (
                            <span className={`font-medium ${val === "∞" ? "text-emerald-400" : val === 0 ? "text-gray-600" : "text-white"}`}>{val}</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Credit Costs */}
      <section className="pb-20">
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="text-2xl font-bold text-center mb-4">{t("pricing.creditCostsTitle")}</h2>
          <p className="text-center text-gray-400 text-sm mb-8">{t("pricing.creditCostsSub")}</p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {[
              { op: "op_chat", cost: 2 }, { op: "op_pipeline", cost: 30 },
              { op: "op_warroom", cost: 10 }, { op: "op_pptx", cost: 8 },
              { op: "op_word", cost: 8 }, { op: "op_excel", cost: 3 },
              { op: "op_study", cost: 15 }, { op: "op_eaAnalysis", cost: 10 },
              { op: "op_eaGen", cost: 15 }, { op: "op_trading", cost: 5 },
              { op: "op_promptFactory", cost: 5 }, { op: "op_apk", cost: 15 },
            ].map(item => (
              <div key={item.op} className="flex items-center justify-between bg-white/5 border border-white/10 rounded-xl px-4 py-3">
                <span className="text-xs text-gray-300">{t(`pricing.${item.op}`)}</span>
                <span className="text-sm font-bold text-indigo-400">{item.cost} 💎</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
