/*
 * HAYO Cipher-7 — UNIVERSAL Premium / Subscription Unlock (unlock_premium.js)
 * ==========================================================================
 * Runtime PoC that forces client-side premium/subscription gates open, covering
 * EVERY common model:
 *   - boolean flags        isPremium()/isPro()/isSubscribed()...   -> true
 *   - negative flags       isExpired()/isTrial()/shouldShowAds()... -> false
 *   - points/credits/coins getBalance()/getPoints()/getTokens()...  -> large
 *   - plan/tier strings    getPlan()/getTier()/getAccountType()...  -> "premium"
 *
 * Technique: Java.enumerateMethods() finds every matching method across ALL
 * loaded classes (obfuscation-resistant for standard getter names) and rewrites
 * its return value by declared type. Every hook is crash-safe.
 *
 */
Java.perform(function () {
    console.log("\n🟢 HAYO Cipher-7: Universal Premium Unlock engaged...\n");

    var FORCE_TRUE = [
        "isPremium",
        "isPro",
        "isVip",
        "isSubscribed",
        "hasSubscription",
        "hasPurchased",
        "isUnlocked",
        "isPaid",
        "isActivated",
        "isBought",
        "isFullVersion",
        "isPremiumUser",
        "isProUser",
        "isPurchased",
        "isProVersion",
        "isAdFree",
        "isAdsRemoved",
        "checkPremium",
        "verifyPremium",
        "isVipUser",
        "isMember",
        "isSubscriber",
        "hasPremium",
        "hasPro",
        "isPremiumActive",
        "isSubscriptionActive",
        "canAccessPremium",
        "isEntitled",
        "hasIsPremium",
        "canIsPremium",
        "checkIsPremium",
        "verifyIsPremium",
        "isIsPremium",
        "getIsPremium",
        "hasActiveIsPremium",
        "isActiveIsPremium",
        "hasValidIsPremium",
        "isPremiumOrNot",
        "isPremiumCheck",
        "isPremiumStatus",
        "isPremiumFlag",
        "isPremiumEnabled",
        "isPremiumValid",
        "isPremiumAsInt",
        "isPremiumAsString",
        "hasIsPro",
        "canIsPro",
        "checkIsPro",
        "verifyIsPro",
        "isIsPro",
        "getIsPro",
        "hasActiveIsPro",
        "isActiveIsPro",
        "hasValidIsPro",
        "isProOrNot",
        "isProCheck",
        "isProStatus",
        "isProFlag",
        "isProEnabled",
        "isProActive",
        "isProValid",
        "isProAsInt",
        "isProAsString",
        "hasIsVip",
        "canIsVip",
        "checkIsVip",
        "verifyIsVip",
        "isIsVip",
        "getIsVip",
        "hasActiveIsVip",
        "isActiveIsVip",
        "hasValidIsVip",
        "isVipOrNot",
        "isVipCheck",
        "isVipStatus",
        "isVipFlag",
        "isVipEnabled",
        "isVipActive",
        "isVipValid",
        "isVipAsInt",
        "isVipAsString",
        "hasIsSubscribed",
        "canIsSubscribed",
        "checkIsSubscribed",
        "verifyIsSubscribed",
        "isIsSubscribed",
        "getIsSubscribed",
        "hasActiveIsSubscribed",
        "isActiveIsSubscribed",
        "hasValidIsSubscribed",
        "isSubscribedOrNot",
        "isSubscribedCheck",
        "isSubscribedStatus",
        "isSubscribedFlag",
        "isSubscribedEnabled",
        "isSubscribedActive",
        "isSubscribedValid",
        "isSubscribedAsInt",
        "isSubscribedAsString",
        "hasHasSubscription",
        "canHasSubscription",
        "checkHasSubscription",
        "verifyHasSubscription",
        "isHasSubscription",
        "getHasSubscription",
        "hasActiveHasSubscription",
        "isActiveHasSubscription",
        "hasValidHasSubscription",
        "hasSubscriptionOrNot",
        "hasSubscriptionCheck",
        "hasSubscriptionStatus",
        "hasSubscriptionFlag",
        "hasSubscriptionEnabled",
        "hasSubscriptionActive",
        "hasSubscriptionValid",
        "hasSubscriptionAsInt",
        "hasSubscriptionAsString",
        "hasHasPurchased",
        "canHasPurchased",
        "checkHasPurchased",
        "verifyHasPurchased",
        "isHasPurchased",
        "getHasPurchased",
        "hasActiveHasPurchased",
        "isActiveHasPurchased",
        "hasValidHasPurchased",
        "hasPurchasedOrNot",
        "hasPurchasedCheck",
        "hasPurchasedStatus",
        "hasPurchasedFlag",
        "hasPurchasedEnabled",
        "hasPurchasedActive",
        "hasPurchasedValid",
        "hasPurchasedAsInt",
        "hasPurchasedAsString",
        "hasIsUnlocked",
        "canIsUnlocked",
        "checkIsUnlocked",
        "verifyIsUnlocked",
        "isIsUnlocked",
        "getIsUnlocked",
        "hasActiveIsUnlocked",
        "isActiveIsUnlocked",
        "hasValidIsUnlocked",
        "isUnlockedOrNot",
        "isUnlockedCheck",
        "isUnlockedStatus",
        "isUnlockedFlag",
        "isUnlockedEnabled",
        "isUnlockedActive",
        "isUnlockedValid",
        "isUnlockedAsInt",
        "isUnlockedAsString",
        "hasIsPaid",
        "canIsPaid",
        "checkIsPaid",
        "verifyIsPaid",
        "isIsPaid",
        "getIsPaid",
        "hasActiveIsPaid",
        "isActiveIsPaid",
        "hasValidIsPaid",
        "isPaidOrNot",
        "isPaidCheck",
        "isPaidStatus",
        "isPaidFlag",
        "isPaidEnabled",
        "isPaidActive",
        "isPaidValid",
        "isPaidAsInt",
        "isPaidAsString",
        "hasIsActivated",
        "canIsActivated",
        "checkIsActivated",
        "verifyIsActivated",
        "isIsActivated",
        "getIsActivated",
        "hasActiveIsActivated",
        "isActiveIsActivated",
        "hasValidIsActivated",
        "isActivatedOrNot",
        "isActivatedCheck",
        "isActivatedStatus",
        "isActivatedFlag",
        "isActivatedEnabled",
        "isActivatedActive",
        "isActivatedValid",
        "isActivatedAsInt",
        "isActivatedAsString",
        "hasIsBought",
        "canIsBought",
        "checkIsBought",
        "verifyIsBought",
        "isIsBought",
        "getIsBought",
        "hasActiveIsBought",
        "isActiveIsBought",
        "hasValidIsBought",
        "isBoughtOrNot",
        "isBoughtCheck",
        "isBoughtStatus",
        "isBoughtFlag",
        "isBoughtEnabled",
        "isBoughtActive",
        "isBoughtValid",
        "isBoughtAsInt",
        "isBoughtAsString",
        "hasIsFullVersion",
        "canIsFullVersion",
        "checkIsFullVersion",
        "verifyIsFullVersion",
        "isIsFullVersion",
        "getIsFullVersion",
        "hasActiveIsFullVersion",
        "isActiveIsFullVersion",
        "hasValidIsFullVersion",
        "isFullVersionOrNot",
        "isFullVersionCheck",
        "isFullVersionStatus",
        "isFullVersionFlag"
    ];
    var FORCE_FALSE = [
        "isExpired",
        "isSubscriptionExpired",
        "isTrial",
        "isTrialExpired",
        "isTrialUser",
        "isFree",
        "isFreeTier",
        "isFreeUser",
        "isLocked",
        "shouldShowAds",
        "isAdEnabled",
        "needsUpgrade",
        "isRestricted",
        "hasIsExpired",
        "canIsExpired",
        "checkIsExpired",
        "verifyIsExpired",
        "isIsExpired",
        "getIsExpired",
        "hasActiveIsExpired",
        "isActiveIsExpired",
        "hasValidIsExpired",
        "isExpiredOrNot",
        "isExpiredCheck",
        "isExpiredStatus",
        "isExpiredFlag",
        "isExpiredEnabled",
        "isExpiredActive",
        "isExpiredValid",
        "isExpiredAsInt",
        "isExpiredAsString",
        "hasIsSubscriptionExpired",
        "canIsSubscriptionExpired",
        "checkIsSubscriptionExpired",
        "verifyIsSubscriptionExpired",
        "isIsSubscriptionExpired",
        "getIsSubscriptionExpired",
        "hasActiveIsSubscriptionExpired",
        "isActiveIsSubscriptionExpired",
        "hasValidIsSubscriptionExpired",
        "isSubscriptionExpiredOrNot",
        "isSubscriptionExpiredCheck",
        "isSubscriptionExpiredStatus",
        "isSubscriptionExpiredFlag",
        "isSubscriptionExpiredEnabled",
        "isSubscriptionExpiredActive",
        "isSubscriptionExpiredValid",
        "isSubscriptionExpiredAsInt",
        "isSubscriptionExpiredAsString",
        "hasIsTrial",
        "canIsTrial",
        "checkIsTrial",
        "verifyIsTrial",
        "isIsTrial",
        "getIsTrial",
        "hasActiveIsTrial",
        "isActiveIsTrial",
        "hasValidIsTrial",
        "isTrialOrNot",
        "isTrialCheck",
        "isTrialStatus",
        "isTrialFlag",
        "isTrialEnabled",
        "isTrialActive",
        "isTrialValid",
        "isTrialAsInt",
        "isTrialAsString",
        "hasIsTrialExpired",
        "canIsTrialExpired",
        "checkIsTrialExpired",
        "verifyIsTrialExpired",
        "isIsTrialExpired",
        "getIsTrialExpired",
        "hasActiveIsTrialExpired",
        "isActiveIsTrialExpired",
        "hasValidIsTrialExpired",
        "isTrialExpiredOrNot",
        "isTrialExpiredCheck",
        "isTrialExpiredStatus",
        "isTrialExpiredFlag",
        "isTrialExpiredEnabled",
        "isTrialExpiredActive",
        "isTrialExpiredValid",
        "isTrialExpiredAsInt",
        "isTrialExpiredAsString",
        "hasIsTrialUser",
        "canIsTrialUser",
        "checkIsTrialUser",
        "verifyIsTrialUser",
        "isIsTrialUser",
        "getIsTrialUser",
        "hasActiveIsTrialUser",
        "isActiveIsTrialUser",
        "hasValidIsTrialUser",
        "isTrialUserOrNot",
        "isTrialUserCheck",
        "isTrialUserStatus",
        "isTrialUserFlag",
        "isTrialUserEnabled",
        "isTrialUserActive",
        "isTrialUserValid",
        "isTrialUserAsInt",
        "isTrialUserAsString",
        "hasIsFree",
        "canIsFree",
        "checkIsFree",
        "verifyIsFree",
        "isIsFree",
        "getIsFree",
        "hasActiveIsFree",
        "isActiveIsFree",
        "hasValidIsFree",
        "isFreeOrNot",
        "isFreeCheck",
        "isFreeStatus",
        "isFreeFlag",
        "isFreeEnabled",
        "isFreeActive",
        "isFreeValid",
        "isFreeAsInt",
        "isFreeAsString",
        "hasIsFreeTier",
        "canIsFreeTier",
        "checkIsFreeTier",
        "verifyIsFreeTier",
        "isIsFreeTier",
        "getIsFreeTier",
        "hasActiveIsFreeTier",
        "isActiveIsFreeTier",
        "hasValidIsFreeTier",
        "isFreeTierOrNot",
        "isFreeTierCheck",
        "isFreeTierStatus",
        "isFreeTierFlag",
        "isFreeTierEnabled",
        "isFreeTierActive",
        "isFreeTierValid",
        "isFreeTierAsInt",
        "isFreeTierAsString",
        "hasIsFreeUser",
        "canIsFreeUser",
        "checkIsFreeUser",
        "verifyIsFreeUser",
        "isIsFreeUser",
        "getIsFreeUser",
        "hasActiveIsFreeUser",
        "isActiveIsFreeUser",
        "hasValidIsFreeUser",
        "isFreeUserOrNot",
        "isFreeUserCheck",
        "isFreeUserStatus",
        "isFreeUserFlag",
        "isFreeUserEnabled",
        "isFreeUserActive",
        "isFreeUserValid",
        "isFreeUserAsInt",
        "isFreeUserAsString",
        "hasIsLocked",
        "canIsLocked",
        "checkIsLocked",
        "verifyIsLocked",
        "isIsLocked",
        "getIsLocked",
        "hasActiveIsLocked",
        "isActiveIsLocked",
        "hasValidIsLocked",
        "isLockedOrNot",
        "isLockedCheck",
        "isLockedStatus",
        "isLockedFlag",
        "isLockedEnabled",
        "isLockedActive",
        "isLockedValid",
        "isLockedAsInt",
        "isLockedAsString",
        "hasShouldShowAds",
        "canShouldShowAds",
        "checkShouldShowAds",
        "verifyShouldShowAds",
        "isShouldShowAds",
        "getShouldShowAds",
        "hasActiveShouldShowAds",
        "isActiveShouldShowAds",
        "hasValidShouldShowAds",
        "shouldShowAdsOrNot",
        "shouldShowAdsCheck",
        "shouldShowAdsStatus",
        "shouldShowAdsFlag",
        "shouldShowAdsEnabled",
        "shouldShowAdsActive",
        "shouldShowAdsValid",
        "shouldShowAdsAsInt",
        "shouldShowAdsAsString",
        "hasIsAdEnabled",
        "canIsAdEnabled",
        "checkIsAdEnabled",
        "verifyIsAdEnabled",
        "isIsAdEnabled",
        "getIsAdEnabled",
        "hasActiveIsAdEnabled",
        "isActiveIsAdEnabled",
        "hasValidIsAdEnabled",
        "isAdEnabledOrNot",
        "isAdEnabledCheck",
        "isAdEnabledStatus",
        "isAdEnabledFlag",
        "isAdEnabledEnabled",
        "isAdEnabledActive",
        "isAdEnabledValid",
        "isAdEnabledAsInt",
        "isAdEnabledAsString",
        "hasNeedsUpgrade",
        "canNeedsUpgrade",
        "checkNeedsUpgrade",
        "verifyNeedsUpgrade",
        "isNeedsUpgrade",
        "getNeedsUpgrade",
        "hasActiveNeedsUpgrade",
        "isActiveNeedsUpgrade",
        "hasValidNeedsUpgrade"
    ];
    var FORCE_BIG = [
        "getPoints",
        "getCredits",
        "getTokens",
        "getBalance",
        "getCoins",
        "getGems",
        "getStars",
        "getPremiumPoints",
        "getRemainingDays",
        "getDaysLeft",
        "getRemainingCredits",
        "hasGetPoints",
        "canGetPoints",
        "checkGetPoints",
        "verifyGetPoints",
        "isGetPoints",
        "getGetPoints",
        "hasActiveGetPoints",
        "isActiveGetPoints",
        "hasValidGetPoints",
        "getPointsOrNot",
        "getPointsCheck",
        "getPointsStatus",
        "getPointsFlag",
        "getPointsEnabled",
        "getPointsActive",
        "getPointsValid",
        "getPointsAsInt",
        "getPointsAsString",
        "hasGetCredits",
        "canGetCredits",
        "checkGetCredits",
        "verifyGetCredits",
        "isGetCredits",
        "getGetCredits",
        "hasActiveGetCredits",
        "isActiveGetCredits",
        "hasValidGetCredits",
        "getCreditsOrNot",
        "getCreditsCheck",
        "getCreditsStatus",
        "getCreditsFlag",
        "getCreditsEnabled",
        "getCreditsActive",
        "getCreditsValid",
        "getCreditsAsInt",
        "getCreditsAsString",
        "hasGetTokens",
        "canGetTokens",
        "checkGetTokens",
        "verifyGetTokens",
        "isGetTokens",
        "getGetTokens",
        "hasActiveGetTokens",
        "isActiveGetTokens",
        "hasValidGetTokens",
        "getTokensOrNot",
        "getTokensCheck",
        "getTokensStatus",
        "getTokensFlag",
        "getTokensEnabled",
        "getTokensActive",
        "getTokensValid",
        "getTokensAsInt",
        "getTokensAsString",
        "hasGetBalance",
        "canGetBalance",
        "checkGetBalance",
        "verifyGetBalance",
        "isGetBalance",
        "getGetBalance",
        "hasActiveGetBalance",
        "isActiveGetBalance",
        "hasValidGetBalance",
        "getBalanceOrNot",
        "getBalanceCheck",
        "getBalanceStatus",
        "getBalanceFlag",
        "getBalanceEnabled",
        "getBalanceActive",
        "getBalanceValid",
        "getBalanceAsInt",
        "getBalanceAsString",
        "hasGetCoins",
        "canGetCoins",
        "checkGetCoins",
        "verifyGetCoins",
        "isGetCoins",
        "getGetCoins",
        "hasActiveGetCoins",
        "isActiveGetCoins",
        "hasValidGetCoins",
        "getCoinsOrNot",
        "getCoinsCheck",
        "getCoinsStatus",
        "getCoinsFlag",
        "getCoinsEnabled",
        "getCoinsActive",
        "getCoinsValid",
        "getCoinsAsInt",
        "getCoinsAsString",
        "hasGetGems",
        "canGetGems",
        "checkGetGems",
        "verifyGetGems",
        "isGetGems",
        "getGetGems",
        "hasActiveGetGems",
        "isActiveGetGems",
        "hasValidGetGems",
        "getGemsOrNot",
        "getGemsCheck",
        "getGemsStatus",
        "getGemsFlag",
        "getGemsEnabled",
        "getGemsActive",
        "getGemsValid",
        "getGemsAsInt",
        "getGemsAsString",
        "hasGetStars",
        "canGetStars",
        "checkGetStars",
        "verifyGetStars",
        "isGetStars",
        "getGetStars",
        "hasActiveGetStars",
        "isActiveGetStars",
        "hasValidGetStars",
        "getStarsOrNot",
        "getStarsCheck",
        "getStarsStatus",
        "getStarsFlag",
        "getStarsEnabled",
        "getStarsActive",
        "getStarsValid",
        "getStarsAsInt",
        "getStarsAsString",
        "hasGetPremiumPoints",
        "canGetPremiumPoints",
        "checkGetPremiumPoints",
        "verifyGetPremiumPoints",
        "isGetPremiumPoints",
        "getGetPremiumPoints",
        "hasActiveGetPremiumPoints",
        "isActiveGetPremiumPoints",
        "hasValidGetPremiumPoints",
        "getPremiumPointsOrNot",
        "getPremiumPointsCheck",
        "getPremiumPointsStatus",
        "getPremiumPointsFlag",
        "getPremiumPointsEnabled",
        "getPremiumPointsActive",
        "getPremiumPointsValid",
        "getPremiumPointsAsInt",
        "getPremiumPointsAsString",
        "hasGetRemainingDays",
        "canGetRemainingDays",
        "checkGetRemainingDays",
        "verifyGetRemainingDays",
        "isGetRemainingDays",
        "getGetRemainingDays",
        "hasActiveGetRemainingDays",
        "isActiveGetRemainingDays",
        "hasValidGetRemainingDays",
        "getRemainingDaysOrNot",
        "getRemainingDaysCheck",
        "getRemainingDaysStatus",
        "getRemainingDaysFlag",
        "getRemainingDaysEnabled",
        "getRemainingDaysActive",
        "getRemainingDaysValid",
        "getRemainingDaysAsInt",
        "getRemainingDaysAsString",
        "hasGetDaysLeft",
        "canGetDaysLeft",
        "checkGetDaysLeft",
        "verifyGetDaysLeft",
        "isGetDaysLeft",
        "getGetDaysLeft",
        "hasActiveGetDaysLeft",
        "isActiveGetDaysLeft",
        "hasValidGetDaysLeft",
        "getDaysLeftOrNot",
        "getDaysLeftCheck",
        "getDaysLeftStatus",
        "getDaysLeftFlag",
        "getDaysLeftEnabled",
        "getDaysLeftActive",
        "getDaysLeftValid",
        "getDaysLeftAsInt",
        "getDaysLeftAsString",
        "hasGetRemainingCredits",
        "canGetRemainingCredits",
        "checkGetRemainingCredits",
        "verifyGetRemainingCredits",
        "isGetRemainingCredits",
        "getGetRemainingCredits",
        "hasActiveGetRemainingCredits",
        "isActiveGetRemainingCredits",
        "hasValidGetRemainingCredits",
        "getRemainingCreditsOrNot",
        "getRemainingCreditsCheck",
        "getRemainingCreditsStatus",
        "getRemainingCreditsFlag",
        "getRemainingCreditsEnabled",
        "getRemainingCreditsActive",
        "getRemainingCreditsValid",
        "getRemainingCreditsAsInt",
        "getRemainingCreditsAsString",
        "isGold",
        "hasIsGold",
        "canIsGold",
        "getIsGold",
        "isPlatinum",
        "hasIsPlatinum",
        "canIsPlatinum",
        "getIsPlatinum",
        "isDiamond",
        "hasIsDiamond",
        "canIsDiamond"
    ];
    var FORCE_PLAN = [
        "getPlan",
        "getTier",
        "getSubscriptionType",
        "getAccountType",
        "getMembership",
        "getSubscriptionPlan",
        "getUserType",
        "getSubscriptionStatus",
        "getPlanName",
        "getRole",
        "hasGetPlan",
        "canGetPlan",
        "checkGetPlan",
        "verifyGetPlan",
        "isGetPlan",
        "getGetPlan",
        "hasActiveGetPlan",
        "isActiveGetPlan",
        "hasValidGetPlan",
        "getPlanOrNot",
        "getPlanCheck",
        "getPlanStatus",
        "getPlanFlag",
        "getPlanEnabled",
        "getPlanActive",
        "getPlanValid",
        "getPlanAsInt",
        "getPlanAsString",
        "hasGetTier",
        "canGetTier",
        "checkGetTier",
        "verifyGetTier",
        "isGetTier",
        "getGetTier",
        "hasActiveGetTier",
        "isActiveGetTier",
        "hasValidGetTier",
        "getTierOrNot",
        "getTierCheck",
        "getTierStatus",
        "getTierFlag",
        "getTierEnabled",
        "getTierActive",
        "getTierValid",
        "getTierAsInt",
        "getTierAsString",
        "hasGetSubscriptionType",
        "canGetSubscriptionType",
        "checkGetSubscriptionType",
        "verifyGetSubscriptionType",
        "isGetSubscriptionType",
        "getGetSubscriptionType",
        "hasActiveGetSubscriptionType",
        "isActiveGetSubscriptionType",
        "hasValidGetSubscriptionType",
        "getSubscriptionTypeOrNot",
        "getSubscriptionTypeCheck",
        "getSubscriptionTypeStatus",
        "getSubscriptionTypeFlag",
        "getSubscriptionTypeEnabled",
        "getSubscriptionTypeActive",
        "getSubscriptionTypeValid",
        "getSubscriptionTypeAsInt",
        "getSubscriptionTypeAsString",
        "hasGetAccountType",
        "canGetAccountType",
        "checkGetAccountType",
        "verifyGetAccountType",
        "isGetAccountType",
        "getGetAccountType",
        "hasActiveGetAccountType",
        "isActiveGetAccountType",
        "hasValidGetAccountType",
        "getAccountTypeOrNot",
        "getAccountTypeCheck",
        "getAccountTypeStatus",
        "getAccountTypeFlag",
        "getAccountTypeEnabled",
        "getAccountTypeActive",
        "getAccountTypeValid",
        "getAccountTypeAsInt",
        "getAccountTypeAsString",
        "hasGetMembership",
        "canGetMembership",
        "checkGetMembership",
        "verifyGetMembership",
        "isGetMembership",
        "getGetMembership",
        "hasActiveGetMembership",
        "isActiveGetMembership",
        "hasValidGetMembership",
        "getMembershipOrNot",
        "getMembershipCheck",
        "getMembershipStatus",
        "getMembershipFlag",
        "getMembershipEnabled",
        "getMembershipActive",
        "getMembershipValid",
        "getMembershipAsInt",
        "getMembershipAsString",
        "hasGetSubscriptionPlan",
        "canGetSubscriptionPlan",
        "checkGetSubscriptionPlan",
        "verifyGetSubscriptionPlan",
        "isGetSubscriptionPlan",
        "getGetSubscriptionPlan",
        "hasActiveGetSubscriptionPlan",
        "isActiveGetSubscriptionPlan",
        "hasValidGetSubscriptionPlan",
        "getSubscriptionPlanOrNot",
        "getSubscriptionPlanCheck",
        "getSubscriptionPlanStatus",
        "getSubscriptionPlanFlag",
        "getSubscriptionPlanEnabled",
        "getSubscriptionPlanActive",
        "getSubscriptionPlanValid",
        "getSubscriptionPlanAsInt",
        "getSubscriptionPlanAsString",
        "hasGetUserType",
        "canGetUserType",
        "checkGetUserType",
        "verifyGetUserType",
        "isGetUserType",
        "getGetUserType",
        "hasActiveGetUserType",
        "isActiveGetUserType",
        "hasValidGetUserType",
        "getUserTypeOrNot",
        "getUserTypeCheck",
        "getUserTypeStatus",
        "getUserTypeFlag",
        "getUserTypeEnabled",
        "getUserTypeActive",
        "getUserTypeValid",
        "getUserTypeAsInt",
        "getUserTypeAsString",
        "hasGetSubscriptionStatus",
        "canGetSubscriptionStatus",
        "checkGetSubscriptionStatus",
        "verifyGetSubscriptionStatus",
        "isGetSubscriptionStatus",
        "getGetSubscriptionStatus",
        "hasActiveGetSubscriptionStatus",
        "isActiveGetSubscriptionStatus",
        "hasValidGetSubscriptionStatus",
        "getSubscriptionStatusOrNot",
        "getSubscriptionStatusCheck",
        "getSubscriptionStatusStatus",
        "getSubscriptionStatusFlag",
        "getSubscriptionStatusEnabled",
        "getSubscriptionStatusActive",
        "getSubscriptionStatusValid",
        "getSubscriptionStatusAsInt",
        "getSubscriptionStatusAsString",
        "hasGetPlanName",
        "canGetPlanName",
        "checkGetPlanName",
        "verifyGetPlanName",
        "isGetPlanName",
        "getGetPlanName",
        "hasActiveGetPlanName",
        "isActiveGetPlanName",
        "hasValidGetPlanName",
        "getPlanNameOrNot",
        "getPlanNameCheck",
        "getPlanNameStatus",
        "getPlanNameFlag",
        "getPlanNameEnabled",
        "getPlanNameActive",
        "getPlanNameValid",
        "getPlanNameAsInt",
        "getPlanNameAsString",
        "hasGetRole",
        "canGetRole",
        "checkGetRole",
        "verifyGetRole",
        "isGetRole",
        "getGetRole",
        "hasActiveGetRole",
        "isActiveGetRole",
        "hasValidGetRole",
        "getRoleOrNot",
        "getRoleCheck",
        "getRoleStatus",
        "getRoleFlag",
        "getRoleEnabled",
        "getRoleActive",
        "getRoleValid",
        "getRoleAsInt",
        "getRoleAsString",
        "isGold",
        "hasIsGold",
        "canIsGold",
        "getIsGold",
        "isPlatinum",
        "hasIsPlatinum",
        "canIsPlatinum",
        "getIsPlatinum",
        "isDiamond",
        "hasIsDiamond",
        "canIsDiamond",
        "getIsDiamond",
        "isElite",
        "hasIsElite",
        "canIsElite",
        "getIsElite",
        "isBeta",
        "hasIsBeta",
        "canIsBeta",
        "getIsBeta",
        "isPatron",
        "hasIsPatron",
        "canIsPatron",
        "getIsPatron",
        "isSupporter",
        "hasIsSupporter",
        "canIsSupporter",
        "getIsSupporter",
        "isDonor",
        "hasIsDonor"
    ];

    var patched = 0;

    function hookGroup(names, kind) {
        names.forEach(function (name) {
            var matches;
            try { matches = Java.enumerateMethods("*!" + name + "/s"); } catch (e) { return; }
            matches.forEach(function (loader) {
                (loader.classes || []).forEach(function (cls) {
                    var clazz;
                    try { clazz = Java.use(cls.name); } catch (e) { return; }
                    (cls.methods || []).forEach(function (m) {
                        try {
                            var fn = clazz[m];
                            if (!fn || !fn.overloads) return;
                            fn.overloads.forEach(function (ov) {
                                var rt = ov.returnType ? ov.returnType.className : "";
                                ov.implementation = function () {
                                    var v = decide(kind, rt);
                                    console.log("🔓 [UNLOCK] " + cls.name + "." + m + "() -> " + v);
                                    return v;
                                };
                                patched++;
                            });
                        } catch (e) {}
                    });
                });
            });
        });
    }

    function decide(kind, rt) {
        if (kind === "true")  return isBool(rt) ? true  : coerce(rt, true);
        if (kind === "false") return isBool(rt) ? false : coerce(rt, false);
        if (kind === "big")   return coerce(rt, 999999);
        if (kind === "plan")  return coerce(rt, "premium");
        return true;
    }
    function isBool(rt) { return rt === "boolean" || rt === "java.lang.Boolean"; }
    function coerce(rt, val) {
        try {
            if (rt === "boolean" || rt === "java.lang.Boolean") return (val === true || val === "premium" || val === 999999);
            if (rt === "int") return 999999;
            if (rt === "long") return 999999;
            if (rt === "float" || rt === "double") return 999999.0;
            if (rt === "java.lang.String") return (typeof val === "string") ? val : String(val);
            if (rt === "java.lang.Integer") return Java.use("java.lang.Integer").$new(999999);
            if (rt === "java.lang.Long") return Java.use("java.lang.Long").$new(999999);
        } catch (e) {}
        return val;
    }

    try { hookGroup(FORCE_TRUE, "true"); } catch (e) {}
    try { hookGroup(FORCE_FALSE, "false"); } catch (e) {}
    try { hookGroup(FORCE_BIG, "big"); } catch (e) {}
    try { hookGroup(FORCE_PLAN, "plan"); } catch (e) {}

    console.log("\n🟢 [DONE] Installed " + patched + " premium-gate hooks. Open the paid feature now.\n");
    console.log("   (If a feature needs SERVER data it may still fail — that means it is server-enforced; see the guide.)\n");

    // ═══════════════════════════════════════════════════════════════════
    // HAYO Cipher-7 — ENHANCED: API Signature Matching + Call Stack
    // ═══════════════════════════════════════════════════════════════════
    // Implementation of Directive 2.1:
    //   - API Hashing/Signature Matching: identify target functions
    //     by return type + parameter signature, not just name
    //   - Call Stack Analysis: detect obfuscated wrapper methods
    //     wrapping known sensitive APIs
    //
    // These run AFTER the initial hookGroup pass, on a 5s delay
    // to allow all classes to load.
    // ═══════════════════════════════════════════════════════════════════

    setTimeout(function () {
        Java.perform(function () {
            // ── 5a) ENHANCED SIGNATURE MATCHING ──────────────────────
            // For classes that don't use standard premium method names,
            // match by signature pattern: boolean return + no params +
            // method name starts with 'is', 'has', 'can', 'check', 'verify'
            var signMatched = 0;
            var SIGNATURE_FINDER_PREFIXES = /^(is|has|can|check|verify|get)/i;

            try {
                Java.enumerateLoadedClasses({
                    onMatch: function (className) {
                        // Scope to app-level classes only
                        if ((className.indexOf("com.") !== 0 && className.indexOf("org.") !== 0) ||
                            className.indexOf("hayo") !== -1 ||
                            className.indexOf("android") === 0 ||
                            className.indexOf("kotlin") === 0 ||
                            className.indexOf("okhttp") === 0 ||
                            className.indexOf("retrofit") === 0 ||
                            className.indexOf("java.") === 0 ||
                            className.indexOf("javax.") === 0 ||
                            signMatched > 50) return;
                        try {
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            for (var i = 0; i < methods.length; i++) {
                                try {
                                    var m = methods[i];
                                    var name = m.getName();
                                    var rt = m.getReturnType().getName();
                                    var params = m.getParameterTypes();

                                    // Rule 1: boolean return + no params + common prefix → premium gate
                                    if ((rt === "boolean" || rt === "java.lang.Boolean") && params.length === 0) {
                                        if (SIGNATURE_FINDER_PREFIXES.test(name) && name !== "is" && name !== "hasCode") {
                                            // Check if this is NOT already hooked by name-based pass
                                            var alreadyHooked = false;
                                            FORCE_TRUE.concat(FORCE_FALSE).forEach(function (pn) {
                                                if (name === pn) alreadyHooked = true;
                                            });
                                            if (!alreadyHooked && !name.match(/^(isFinishing|isDestroyed|isShowing|isShown|isEnabled|isAttached|isActivated|isInitial|isRunning|isAlive|isConnected|isBound|isActive|isLoaded)$/i)) {
                                                try {
                                                    var fn = clazz[name];
                                                    if (fn && fn.overloads) {
                                                        fn.overloads.forEach(function (ov) {
                                                            if (ov.returnType && ov.returnType.className === "boolean") {
                                                                var origImpl = ov.implementation;
                                                                ov.implementation = function () {
                                                                    console.log("🔓 [UNLOCK+SIG] " + className + "." + name + "() -> true [signature-matched]");
                                                                    return true;
                                                                };
                                                                signMatched++;
                                                                patched++;
                                                            }
                                                        });
                                                    }
                                                } catch (e) {}
                                            }
                                        }
                                    }

                                    // Rule 2: String return + no params → possible plan/tier getter
                                    if ((rt === "java.lang.String" || rt === "java.lang.String") && params.length === 0) {
                                        if (name.match(/^(get|is|has)/i) &&
                                            name.match(/[Pp]lan|[Tt]ier|[Rr]ole|[Tt]ype|[Ll]evel|[Ss]tatus|[Mm]embership|[Ss]ubscription/i)) {
                                            var alreadyHooked = false;
                                            FORCE_PLAN.forEach(function (pn) {
                                                if (name === pn) alreadyHooked = true;
                                            });
                                            if (!alreadyHooked) {
                                                try {
                                                    var fn = clazz[name];
                                                    if (fn && fn.overloads) {
                                                        fn.overloads.forEach(function (ov) {
                                                            if (ov.returnType && ov.returnType.className === "java.lang.String") {
                                                                var origImpl = ov.implementation;
                                                                ov.implementation = function () {
                                                                    console.log("🔓 [UNLOCK+SIG] " + className + "." + name + "() -> \"premium\" [signature-matched]");
                                                                    return "premium";
                                                                };
                                                                signMatched++;
                                                                patched++;
                                                            }
                                                        });
                                                    }
                                                } catch (e) {}
                                            }
                                        }
                                    }

                                    // Rule 3: int/long return + no params → possible coin/point/credit getter
                                    if ((rt === "int" || rt === "long" || rt === "java.lang.Integer" || rt === "java.lang.Long") && params.length === 0) {
                                        if (name.match(/^(get|is|has)/i) &&
                                            name.match(/[Cc]oin|[Pp]oint|[Cc]redit|[Bb]alance|[Tt]oken|[Gg]em|[Ss]tar|[Gg]old|[Ss]core|[Xx]p|[Ll]evel/i)) {
                                            try {
                                                var fn = clazz[name];
                                                if (fn && fn.overloads) {
                                                    fn.overloads.forEach(function (ov) {
                                                        var ovRt = ov.returnType ? ov.returnType.className : "";
                                                        if (ovRt.indexOf("int") !== -1 || ovRt.indexOf("long") !== -1) {
                                                            var origImpl = ov.implementation;
                                                            ov.implementation = function () {
                                                                console.log("💰 [UNLOCK+BALANCE] " + className + "." + name + "() -> 999999 [signature-matched]");
                                                                return 999999;
                                                            };
                                                            signMatched++;
                                                            patched++;
                                                        }
                                                    });
                                                }
                                            } catch (e) {}
                                        }
                                    }
                                } catch (e) {}
                            }
                        } catch (e) {}
                    },
                    onComplete: function () {
                        console.log("🟢 [ENHANCED] Signature-matched " + signMatched + " additional premium gates (beyond name-based).");
                    }
                });
            } catch (e) {}

            // ── 5b) CALL STACK ANALYSIS ─────────────────────────────
            // Monitor call stacks of known premium/billing APIs to detect
            // obfuscated wrapper methods that invoke them indirectly.
            try {
                var BILLING_CLASSES = [
                    "com.android.billingclient.api.BillingClient",
                    "com.android.billingclient.api.BillingClientImpl",
                    "com.android.billingclient.api.Purchase",
                    "com.android.billingclient.api.SkuDetails",
                    "com.revenuecat.purchases.Purchases",
                    "com.revenuecat.purchases.PurchaserInfo",
                    "com.revenuecat.purchases.CustomerInfo",
                ];

                BILLING_CLASSES.forEach(function (cn) {
                    try {
                        var clazz = Java.use(cn);
                        var clsMethods = clazz.class.getDeclaredMethods();
                        for (var i = 0; i < clsMethods.length; i++) {
                            try {
                                var mName = clsMethods[i].getName();
                                var fn = clazz[mName];
                                if (fn && fn.overloads) {
                                    fn.overloads.forEach(function (ov) {
                                        var origImpl = ov.implementation;
                                        ov.implementation = function () {
                                            try {
                                                var trace = Java.use("android.util.Log").getStackTraceString(
                                                    new Java.use("java.lang.Exception").$new());
                                                if (trace && trace.length > 50) {
                                                    var lines = trace.split("\n");
                                                    var wrapper = null;
                                                    var appFrames = [];
                                                    for (var t = 0; t < lines.length && t < 12; t++) {
                                                        var line = lines[t];
                                                        // Look for app-code frames that wrap this API
                                                        var m2 = line.match(/at\s+([a-zA-Z0-9_.$]+\.([a-zA-Z0-9_$]+))\(/);
                                                        if (m2 && m2[1].indexOf(cn) === -1 &&
                                                            m2[1].indexOf("java.") === -1 &&
                                                            m2[1].indexOf("android.") === -1 &&
                                                            m2[1].indexOf("dalvik.") === -1 &&
                                                            (m2[1].indexOf("com.") === 0 || m2[1].indexOf("org.") === 0)) {
                                                            appFrames.push(m2[1]);
                                                        }
                                                    }
                                                    if (appFrames.length > 0) {
                                                        var appCaller = appFrames[0];
                                                        // Check if caller is obfuscated (short name like a.b.c.a() )
                                                        if (/(\.[a-z]\(|\.\w{1,3}\(|\$\d+\(|lambda\()/.test(appCaller)) {
                                                            console.log("🔎 [CALLSTACK] Obfuscated wrapper calling " + cn + "." + mName + ": " + appCaller);
                                                            send({type:"premium", kind:"obfuscated_wrapper", detail: JSON.stringify({
                                                                target: cn + "." + mName,
                                                                wrapper: appCaller,
                                                                stack: appFrames.slice(0, 3).join(" <- ")
                                                            }).substring(0, 400)});

                                                            // Try to re-hook the wrapper method too
                                                            try {
                                                                var wrapperParts = appCaller.split(".");
                                                                var wrapperMethod = wrapperParts.pop();
                                                                var wrapperClass = wrapperParts.join(".");
                                                                var wClazz = Java.use(wrapperClass);
                                                                if (wClazz && wClazz[wrapperMethod] && wClazz[wrapperMethod].overloads) {
                                                                    wClazz[wrapperMethod].overloads.forEach(function (wOv) {
                                                                        var origWImpl = wOv.implementation;
                                                                        wOv.implementation = function () {
                                                                            console.log("🔓 [WRAPPER-REHOOK] Calling " + appCaller + " -> true (via obfuscated wrapper re-hook)");
                                                                            return true;
                                                                        };
                                                                    });
                                                                }
                                                            } catch (e) {}
                                                        }
                                                    }
                                                }
                                            } catch (e) {}
                                            return origImpl.apply(this, arguments);
                                        };
                                    });
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                });
            } catch (e) {}

            console.log("🟢 [ENHANCED] Signature matching + call stack analysis deployed.\n");
        });
    }, 5000);

    console.log("   (If a feature needs SERVER data it may still fail — that means it is server-enforced; see the guide.)\n");
});
