package io.github.capitan0n.droynis.checks.base

/**
 * Published boot ROM flaws, for INTG-1013. Hand-kept: no source publishes them in a form a script
 * could read. Rules for an entry:
 *
 * - The flaw is in the boot ROM (or, for Unisoc's FDL1, in the signed loader the boot ROM runs), so
 *   no update fixes it on chips already made.
 * - Every chip is named by the vendor's advisory, the CVE record or the researchers' write-up, given
 *   in [ChipFlaw.source]. Names that are one die sold under several model numbers are one [Chip].
 * - Ids are the names Android reports: `Build.SOC_MODEL`, `ro.board.platform`, `Build.HARDWARE`,
 *   `Build.BOARD`, lowercase. A platform name several dies share goes in [SHARED_PLATFORMS].
 * - Phones and tablets only: TVs, modems and IoT parts are left out.
 */
internal object ChipFlawData {
    /** When every entry was last checked against its source. */
    const val DATE = "2026-11-15"

    /**
     * Qualcomm builds several dies on one platform name, and older phones report only that name in
     * `ro.board.platform`. These include a listed die and others that aren't listed.
     */
    val SHARED_PLATFORMS: Map<String, String> = mapOf(
        "msm8916" to "the MSM8916 and other chips such as the MSM8939 (Snapdragon 615)",
        "msm8952" to "the MSM8952 and other chips such as the MSM8956 (Snapdragon 650)",
    )

    val FLAWS: List<ChipFlaw> = listOf(
        ChipFlaw(
            id = "CVE-2026-25262",
            title = "Qualcomm Emergency Download mode boot ROM memory corruption",
            needs = "a USB cable and the phone restarted into Emergency Download mode",
            chips = listOf(
                Chip("Snapdragon 210/212 (MSM8909)", "msm8909"),
                Chip("Snapdragon 410/412 (MSM8916)", "msm8916"),
                Chip("Snapdragon 617 (MSM8952)", "msm8952"),
            ),
            source = "https://docs.qualcomm.com/product/publicresources/securitybulletin/may-2026-bulletin.html",
            note = "the bulletin also lists the MDM9x07, MDM9x45, MDM9x55, MDM9x65 and SDX50 modems",
        ),
        ChipFlaw(
            id = "MT8163V voltage glitch",
            title = "MediaTek boot ROM signature check skipped by voltage glitching",
            needs = "the case opened and a glitching rig wired to the chip's power supply",
            chips = listOf(Chip("MT8163", "mt8163")),
            source = "https://www.nccgroup.com/research/there-s-a-hole-in-your-soc-glitching-the-mediatek-bootrom/",
            note = "NCC Group tested the MT8163V only; other MediaTek chips start the same way",
        ),
        ChipFlaw(
            id = "MT6878 EMFI",
            title = "MediaTek Dimensity 7300 boot ROM electromagnetic fault injection",
            needs = "a USB cable and an electromagnetic fault-injection rig",
            chips = listOf(Chip("Dimensity 7300 (MT6878)", "mt6878")),
            source = "https://www.ledger.com/blog-is-your-smartphones-hardware-safe",
            note = "Ledger Donjon reached the chip's highest privilege level (EL3); MediaTek considers such attacks out of scope",
        ),
        ChipFlaw(
            id = "CVE-2022-38691, CVE-2022-38693, CVE-2022-38694",
            title = "Unisoc boot ROM certificate check, unchecked write address and FDL1 overflow",
            needs = "a USB cable and the phone started in Unisoc's download mode",
            chips = listOf(
                Chip("SC9863A", "sc9863a", "sp9863a"),
                Chip("T310", "t310", "ums312"),
                Chip("T610/T618", "t610", "t618", "ums512"),
                Chip("T606/T612/T616", "t606", "t612", "t616", "ums9230"),
                Chip("T760/T770/T820/S8000", "t760", "t770", "t820", "s8000", "ums9620"),
                Chip("T750/T765", "t750", "t765", "ums9621"),
            ),
            source = "https://www.nccgroup.com/research-blog/there-s-another-hole-in-your-soc-unisoc-rom-vulnerabilities/",
            note = "CVE-2022-38691 and -38694 list only the SC9863A, T310, T610 and T618; CVE-2022-38693 lists all",
        ),
        ChipFlaw(
            id = "kamakiri",
            title = "MediaTek boot ROM USB download exploit",
            needs = "a USB cable and the phone started in the boot ROM's download mode",
            chips = listOf(
                Chip("MT6572", "mt6572"),
                Chip("MT6580", "mt6580"),
                Chip("MT6582", "mt6582", "mt6574", "mt8382"),
                Chip("MT6592", "mt6592", "mt8392"),
                Chip("MT6595", "mt6595"),
                Chip("MT6735", "mt6735", "mt8735"),
                Chip("MT6737", "mt6737"),
                Chip("MT6739", "mt6739", "mt6731", "mt8765"),
                Chip("MT6753", "mt6753"),
                Chip("Helio P10 (MT6755)", "mt6755"),
                Chip("Helio P20/P25 (MT6757)", "mt6757"),
                Chip("Helio A22/P22 (MT6761/MT6762)", "mt6761", "mt6762", "mt8761", "mt8766"),
                Chip("Helio P23 (MT6763)", "mt6763"),
                Chip("Helio P35/G35 (MT6765)", "mt6765", "mt8768"),
                Chip("Helio P65/G85 (MT6768/MT6769)", "mt6768", "mt6769"),
                Chip("Helio P60/P70 (MT6771)", "mt6771", "mt8183", "mt8385", "mt8666"),
                Chip("Helio P90 (MT6779)", "mt6779"),
                Chip("Helio G90 (MT6785)", "mt6785"),
                Chip("Helio X10 (MT6795)", "mt6795"),
                Chip("Helio X20/X23/X25/X27 (MT6797)", "mt6797", "mt6767"),
                Chip("Helio X30 (MT6799)", "mt6799"),
                Chip("Dimensity 700 (MT6833)", "mt6833"),
                Chip("Dimensity 720 (MT6853)", "mt6853"),
                Chip("Dimensity 800/820 (MT6873)", "mt6873"),
                Chip("Dimensity 1000 (MT6885)", "mt6885", "mt6883", "mt6889"),
                Chip("MT8127", "mt8127"),
                Chip("MT8163", "mt8163"),
                Chip("MT8167", "mt8167", "mt8362"),
                Chip("MT8173", "mt8173"),
            ),
            source = "https://github.com/MTK-bypass/exploits_collection",
            note = "many phone makers turn off the boot ROM's download mode, which blocks it",
        ),
        ChipFlaw(
            id = "exynos-usbdl",
            title = "Samsung Exynos boot ROM USB download mode exploit",
            needs = "the phone's bootloader damaged so it falls back to USB download mode, and a USB cable",
            chips = listOf(
                Chip("Exynos 8890", "exynos8890", "samsungexynos8890", "universal8890"),
                Chip("Exynos 8895", "exynos8895", "samsungexynos8895", "universal8895"),
            ),
            source = "https://fredericb.info/2020/06/exynos-usbdl-unsigned-code-loader-for-exynos-bootrom.html",
        ),
        ChipFlaw(
            id = "CVE-2018-6242",
            title = "NVIDIA Tegra X1 recovery mode (RCM) buffer overflow",
            needs = "a USB cable and the device started in recovery mode",
            chips = emptyList(),
            // Android doesn't name the Tegra X1 apart from its fixed revision (T210B01), so the tablet is listed by model.
            devices = listOf(ListedDevice("Tegra X1 (Pixel C)", "Google", "Pixel C")),
            source = "https://nvidia.custhelp.com/app/answers/detail/a_id/4660",
            note = "NVIDIA names no devices; the Pixel C is the Tegra X1 tablet that runs Android 8",
        ),
        ChipFlaw(
            id = "CVE-2022-38695, CVE-2022-38696",
            title = "Unisoc boot ROM unchecked command index and payload size",
            needs = "a USB cable and the phone started in Unisoc's download mode",
            chips = listOf(
                Chip("SC9863A", "sc9863a", "sp9863a"),
                Chip("T310", "t310", "ums312"),
                Chip("T610/T618", "t610", "t618", "ums512"),
                Chip("T606/T612/T616", "t606", "t612", "t616", "ums9230"),
                Chip("T760/T770/T820/S8000", "t760", "t770", "t820", "s8000", "ums9620"),
                Chip("T750/T765", "t750", "t765", "ums9621"),
            ),
            source = "https://www.nccgroup.com/research-blog/there-s-another-hole-in-your-soc-unisoc-rom-vulnerabilities/",
            note = "CVE-2022-38695 doesn't list the T750 and T765",
        ),
    )
}
