//! Static OTA choices for the install browser, arranged by model and ColorOS generation.

/// A version displayed in the browser and its exact ZIP download URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtaPackage {
    pub version: &'static str,
    pub url: &'static str,
}

/// Packages from one ColorOS generation for a single model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationGroup {
    pub generation: &'static str,
    pub packages: &'static [OtaPackage],
}

/// All represented ColorOS generations for one model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelGroup {
    pub model: &'static str,
    pub generations: &'static [GenerationGroup],
}

#[cfg(test)]
mod tests {
    use super::GROUPS;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_contains_43_distinct_https_zip_urls() {
        let mut models = BTreeSet::new();
        let mut all_urls = BTreeSet::new();
        let mut count = 0;
        for model in GROUPS {
            assert!(!model.model.trim().is_empty() && models.insert(model.model));
            assert!(!model.generations.is_empty(), "{} has no generations", model.model);
            let mut generations = BTreeSet::new();
            for group in model.generations {
                assert!(!group.generation.trim().is_empty() && generations.insert(group.generation));
                assert!(!group.packages.is_empty(), "{} {} has no packages", model.model, group.generation);
                for package in group.packages {
                    assert!(!package.version.trim().is_empty(), "missing version for {}", package.url);
                    let address = package.url.strip_prefix("https://").expect("OTA URLs must use HTTPS");
                    let (host, path) = address.split_once('/').expect("OTA URLs must have a host and path");
                    let file = path.split(['?', '#']).next().unwrap_or_default();
                    assert!(!host.is_empty() && file.ends_with(".zip"), "invalid ZIP URL: {}", package.url);
                    assert!(!package.url.chars().any(char::is_whitespace), "whitespace in URL: {}", package.url);
                    assert!(all_urls.insert(package.url), "duplicate OTA URL: {}", package.url);
                    count += 1;
                }
            }
        }
        assert_eq!(count, 43);
    }
}

/// User-provided download choices, in the original model and generation order.
pub static GROUPS: &[ModelGroup] = &[
    ModelGroup {
        model: "PGZ110",
        generations: &[
            GenerationGroup {
                generation: "12.1",
                packages: &[
                    OtaPackage {
                        version: "A.04",
                        url: "https://component-ota-afs.coloros.com/component-ota/22/05/26/7f85af83ab5f406da597b0d38c65a95b.zip",
                    },
                    OtaPackage {
                        version: "A.05",
                        url: "https://component-ota-afs.coloros.com/component-ota/22/07/14/bc4dfbb1d06445f1b7abb1e30f3ba4a7.zip",
                    },
                    OtaPackage {
                        version: "A.06",
                        url: "https://component-ota-afs.coloros.com/component-ota/22/08/18/6c639cac5b8e416a9ab8ee6d1f05e539.zip",
                    },
                    OtaPackage {
                        version: "A.08",
                        url: "https://component-ota-afs.coloros.com/component-ota/22/09/20/d0e15f778aaa40619539d1982a275375.zip",
                    },
                    OtaPackage {
                        version: "A.10",
                        url: "https://gauss-compotacostauto-cn.allawnfs.com/remove-3acdd48f8f8d39e549fedb3fdbb8c25e/component-ota/22/11/17/c6ff08cf79cb4f5e8cacd3b36dbb6256.zip",
                    },
                    OtaPackage {
                        version: "A.11",
                        url: "https://gauss-compotacostauto-cn.allawnfs.com/remove-bd4a8fd5aaae2321d41995fbf047a908/component-ota/22/12/27/0ec18e754ce84db88ecb16acf3afeeca.zip",
                    },
                    OtaPackage {
                        version: "A.13",
                        url: "https://gauss-compotacostauto-cn.allawnfs.com/remove-355f0bcef8eaa432c5aa160eb87188c5/component-ota/23/02/09/b1018bd460454083a2073b4b86acd311.zip",
                    },
                ],
            },
            GenerationGroup {
                generation: "13.0.0",
                packages: &[
                    OtaPackage {
                        version: "C.01",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-44c6a062ee58073fb658e69d5b823b78/component-ota/22/12/16/fd070c395083417688b93b9b9e308e8a.zip",
                    },
                    OtaPackage {
                        version: "C.02",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-e58a9d92b6fcd122c891624eba85b1e3/component-ota/23/01/06/636fb9d2856945129cdcdf5f9a769ca9.zip",
                    },
                    OtaPackage {
                        version: "C.03",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-971f0c18c4efa239387274caeaeac135/component-ota/23/02/02/ffcd04986b104642bbaa215a06386fce.zip",
                    },
                    OtaPackage {
                        version: "C.04",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-a59482a669ab0ff9c6bc3b79d499c632/component-ota/23/03/22/ea2b7f9252df4be09f1cbea47de1c752.zip",
                    },
                    OtaPackage {
                        version: "C.05",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-79e4d45b55bf58338f504b0e4832dcf6/component-ota/23/04/04/15a2884fd35f4e16978e2a0fb55e23ae.zip",
                    },
                ],
            },
            GenerationGroup {
                generation: "13.1.0",
                packages: &[
                    OtaPackage {
                        version: "13.1.0.121（C.32）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-5d1630f9aaf58f1678933309c158e8bd/component-ota/23/05/25/823f80ca01984c25bc70fe2a98ec3546.zip",
                    },
                    OtaPackage {
                        version: "13.1.0.180（C.33）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-62590875cd5200907cf2162286021295/component-ota/23/06/07/c0aa9010489a44a1a1819e532217c9f1.zip",
                    },
                    OtaPackage {
                        version: "13.1.0.182（C.34）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-6338212932c9ae2694b2d7c6c9cc6408/component-ota/23/06/30/b18b99468cce43b39bc92cf584db6942.zip",
                    },
                    OtaPackage {
                        version: "13.1.0.190（C.35）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-d52bf7cda57f84ee3e41aa0de84d8be4/component-ota/23/08/17/b90e9ff8b81e4f3389fc70141e4757a7.zip",
                    },
                    OtaPackage {
                        version: "13.1.0.200（C.36）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-c87fb13a1fed9872d9b06828f5bba047/component-ota/23/10/23/0194ea49c8a244f6aba3ac48325f06c4.zip",
                    },
                    OtaPackage {
                        version: "13.1.0.210（C.37）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-ad32334a7b5708db73745ab509c49e41/component-ota/23/12/21/6288b142116840b592874f66b67309e1.zip",
                    },
                    OtaPackage {
                        version: "13.1.0.211（C.38）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-1a29f2bd2d94a5a4defdc244759000b2/component-ota/24/02/01/d078e2d254a3490fb655ff880e4755c7.zip",
                    },
                ],
            },
            GenerationGroup {
                generation: "14.0.0",
                packages: &[
                    OtaPackage {
                        version: "14.0.0.81（F.21）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-26470471d7d3db753ddfe31209f618a4/component-ota/23/11/08/013b5ebd2c644392858f9271f843702d.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.82（F.22）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-78517eab8be127f4c01fed29807ad505/component-ota/23/11/24/ffd885c4aeda498ba2f18cdff368803f.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.200（F.30）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-91ea86b7f83b496ab5423b9844730d88/component-ota/23/12/19/59c34853efdd4163ac945d4a0fdda7a7.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.203（F.31）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-9040950f54d699ddce8727f50d24ade6/component-ota/24/02/01/8043ce2d4fd64b479a2b8986e98bb6c4.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.500（F.32）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-3e9bf90d19c45ca29db2ed5f44ed1d7f/component-ota/24/02/27/217c785beade4bcca7d8ef506cdf95b4.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.610（F.33）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-1e0ca451681dbe9d9a2a979a0602e81a/component-ota/24/04/12/b41b3c0f3ce34275ba0869a8309eaba9.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.620（F.34）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-e7865fdff2704808af78bbd3007c334d/component-ota/24/06/19/87e32ee25a9540aa96120ab205f78db6.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.630（F.35）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-61fe737c7d7bb6b24780fc8c06c22c43/component-ota/24/08/21/d969826f68e6412ebc85faa2638a9a25.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.640（F.36）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-512b16cd4cfb4974740b7a5b771d589e/component-ota/24/10/23/6dfb469dac894f6d97932188011cf757.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.650（F.37）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-f2d2b9732267844d850063622bafaf2f/component-ota/24/12/24/7fbfbb7b7b154b6d9056dd6667285544.zip",
                    },
                ],
            },
            GenerationGroup {
                generation: "15.0.0",
                packages: &[
                    OtaPackage {
                        version: "15.0.0.501（H.12）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-647e72dd23fd23180188d5b38bbe9af1/component-ota/25/02/17/cee877d4176b406e9b15c2290d893383.zip",
                    },
                    OtaPackage {
                        version: "15.0.0.700（H.13）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-7e300b81349a00fc5b057d48a526f39a/component-ota/25/03/27/5b984d6d84894c87ac689644d3d48868.zip",
                    },
                    OtaPackage {
                        version: "15.0.0.800（H.14）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-00100e2fa0744b1ad7fee4f13391a382/component-ota/25/04/22/0f640f59d10643e5a863bf6df1846c60.zip",
                    },
                    OtaPackage {
                        version: "15.0.0.1101（H.15）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-7be2408e97d5a496d5848b5b4af76e63/component-ota/25/07/22/7bbadd93a3c947f99379188d562c08a0.zip",
                    },
                    OtaPackage {
                        version: "15.0.0.1301（H.16）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-1c224effca1880c8e0879334c3312192/component-ota/25/10/21/4f0cfe2627804904905a7bbeba4a9a84.zip",
                    },
                    OtaPackage {
                        version: "15.0.0.1600（H.17）",
                        url: "https://gauss-componentotacostmanual-cn.allawnfs.com/remove-02a51081e16643ac72f02d4b13376ebf/component-ota/26/01/15/b9e24307e1084eb0adbdc9784b7da3e1.zip",
                    },
                ],
            },
        ],
    },
    ModelGroup {
        model: "PGJM10",
        generations: &[
            GenerationGroup {
                generation: "12.1",
                packages: &[
                    OtaPackage {
                        version: "A.17",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-5ff103200adac3faf579ff95a052c96c/component-ota/22/12/23/a08a8fdee2cc4e418fef847424322f6b.zip",
                    },
                    OtaPackage {
                        version: "A.18",
                        url: "https://gauss-componentotacostmanual-cn.allawnfs.com/remove-362f9c544a3f188bfeadbbd56ae1ecb7/component-ota/23/02/09/bac36f9a9fc347b688101df34c636478.zip",
                    },
                ],
            },
            GenerationGroup {
                generation: "13.0",
                packages: &[
                    OtaPackage {
                        version: "C.05",
                        url: "https://gauss-componentotacostmanual-cn.allawnfs.com/remove-b30315e232ac3c6f8a445bdf4ed2c9a4/component-ota/23/04/04/8777328862ee42289a1354b457d74ad2.zip",
                    },
                    OtaPackage {
                        version: "C.11",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-70d3401f15c330fc8f80b8867a4406bd/component-ota/24/02/04/e9bbf5dece1e4f5d8dcf0142dfde7302.zip",
                    },
                ],
            },
            GenerationGroup {
                generation: "14.0",
                packages: &[
                    OtaPackage {
                        version: "14.0.0.500（CN01，F.32）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-e4ad109ff27e33c04d82170a6154606e/component-ota/24/02/24/4e8e76eb5771412693e4b257a50336c4.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.2900（CN01，F.43）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-a06e7ae2ce4afddb342056b03f48b5c3/component-ota/26/03/19/4f1575c5e2694949b96afba968d76653.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.3001（CN01，F.44）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-d9c5ab51952cb64d05608bb1f009a5e8/component-ota/26/06/24/7f901ca90e1646b6b291c1384ff84564.zip",
                    },
                    OtaPackage {
                        version: "14.0.0.3101（CN01，F.45）",
                        url: "https://gauss-opexcostmanual-cn.allawnfs.com/remove-79090d9b4446384f27f5e2c8c716181f/component-ota/26/09/16/23675598517c4ed4adc9b9ac4f0336b9.zip",
                    },
                ],
            },
        ],
    },
];
