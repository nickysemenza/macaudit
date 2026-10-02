use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use macaudit::inventory::{DiskInventory, MemoryBudget};
use macaudit::scan::walk::DirNode;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn inventory_queries(criterion: &mut Criterion) {
    let node = DirNode {
        name: "/fixture".into(),
        children: (0..100_000)
            .map(|index| DirNode {
                name: format!("folder-{index}").into(),
                alloc: index as u64,
                ..DirNode::default()
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        ..DirNode::default()
    };
    let inventory = DiskInventory::from_node(&node, MemoryBudget::new(128 * 1024 * 1024)).unwrap();
    criterion.bench_function("wide directory bounded scene", |benchmark| {
        benchmark.iter(|| {
            black_box(inventory.summary_at_bounded(
                Path::new("/fixture"),
                Path::new("/fixture"),
                1,
                500,
            ))
        })
    });
}

fn scan_to_json(criterion: &mut Criterion) {
    let fixture = tempfile::tempdir().unwrap();
    for folder in 0..100 {
        let path = fixture.path().join(format!("folder-{folder:03}"));
        std::fs::create_dir(&path).unwrap();
        for file in 0..100 {
            std::fs::write(path.join(format!("file-{file:03}")), [0u8; 4096]).unwrap();
        }
    }
    let mut samples = Vec::with_capacity(30);
    let mut serialized_bytes = 0;
    for _ in 0..31 {
        let started = Instant::now();
        let result = macaudit::scan::walk::walk(
            fixture.path(),
            macaudit::scan::walk::WalkOptions {
                keep_tree: false,
                keep_inventory: true,
                top_n: 128,
                ..Default::default()
            },
            &macaudit::scan::walk::NoVisitor,
            None,
            &|| false,
        );
        let inventory = result.inventory.unwrap();
        let scene = inventory
            .summary_at_bounded(fixture.path(), fixture.path(), 2, 500)
            .unwrap();
        serialized_bytes = serde_json::to_vec(&scene).unwrap().len();
        samples.push(started.elapsed());
    }
    samples.remove(0);
    samples.sort_unstable();
    eprintln!(
        "warm scan-to-JSON: samples=30 p50={:.3}ms p95={:.3}ms serialized={}B engine_peak={}B",
        samples[15].as_secs_f64() * 1000.0,
        samples[28].as_secs_f64() * 1000.0,
        serialized_bytes,
        MemoryBudget::shared().peak()
    );
    criterion.bench_function(
        "10000 files scan to bounded serialized scene",
        |benchmark| {
            benchmark.iter(|| {
                let result = macaudit::scan::walk::walk(
                    fixture.path(),
                    macaudit::scan::walk::WalkOptions {
                        keep_tree: false,
                        keep_inventory: true,
                        top_n: 128,
                        ..Default::default()
                    },
                    &macaudit::scan::walk::NoVisitor,
                    None,
                    &|| false,
                );
                let inventory = result.inventory.unwrap();
                let scene = inventory
                    .summary_at_bounded(fixture.path(), fixture.path(), 2, 500)
                    .unwrap();
                black_box(serde_json::to_vec(&scene).unwrap())
            })
        },
    );
}

struct PublicationProbe {
    started: Instant,
    first_useful: Arc<Mutex<Option<Duration>>>,
}

impl macaudit::scan::walk::Visitor for PublicationProbe {
    fn inventory_publisher(&self, root: &Path) -> Option<macaudit::scan::walk::InventoryPublisher> {
        let root = root.to_path_buf();
        let started = self.started;
        let first_useful = self.first_useful.clone();
        Some(Arc::new(move |inventory| {
            let mut first_useful = first_useful.lock().unwrap();
            if first_useful.is_some() {
                return;
            }
            if inventory
                .summary_at_bounded(&root, &root, 2, 500)
                .is_some_and(|scene| scene.alloc > 0)
            {
                *first_useful = Some(started.elapsed());
            }
        }))
    }
}

fn fixture_shape(shape: &str) -> tempfile::TempDir {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    match shape {
        "flat" => {
            for index in 0..10_000 {
                std::fs::write(root.join(format!("file-{index:05}")), [0u8; 4096]).unwrap();
            }
        }
        "wide" => {
            for index in 0..10_000 {
                let directory = root.join(format!("dir-{index:05}"));
                std::fs::create_dir(&directory).unwrap();
                std::fs::write(directory.join("file"), [0u8; 4096]).unwrap();
            }
        }
        "deep" => {
            let mut directory = root.to_path_buf();
            for depth in 0..128 {
                directory.push(format!("d{depth}"));
                std::fs::create_dir(&directory).unwrap();
                for index in 0..32 {
                    std::fs::write(directory.join(format!("file-{index}")), [0u8; 4096]).unwrap();
                }
            }
        }
        "hardlinked" => {
            let sources: Vec<PathBuf> = (0..100)
                .map(|index| {
                    let path = root.join(format!("source-{index:03}"));
                    std::fs::write(&path, [0u8; 4096]).unwrap();
                    path
                })
                .collect();
            for index in 0..9900 {
                std::fs::hard_link(
                    &sources[index % sources.len()],
                    root.join(format!("link-{index:05}")),
                )
                .unwrap();
            }
        }
        _ => unreachable!(),
    }
    fixture
}

fn observe_fixture(root: &Path) -> (Duration, Duration, usize, u64, u64) {
    let started = Instant::now();
    let probe = PublicationProbe {
        started,
        first_useful: Arc::new(Mutex::new(None)),
    };
    let result = macaudit::scan::walk::walk(
        root,
        macaudit::scan::walk::WalkOptions {
            keep_tree: false,
            keep_inventory: true,
            top_n: 128,
            ..Default::default()
        },
        &probe,
        None,
        &|| false,
    );
    assert!(result.complete);
    let files = result.root.files;
    let directories = result.root.dirs;
    let inventory = result.inventory.unwrap();
    let scene = inventory.summary_at_bounded(root, root, 2, 500).unwrap();
    let serialized_bytes = serde_json::to_vec(&scene).unwrap().len();
    let elapsed = started.elapsed();
    let first_useful = probe.first_useful.lock().unwrap().unwrap_or(elapsed);
    (elapsed, first_useful, serialized_bytes, files, directories)
}

fn representative_shapes(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("fixture publication to JSON");
    for shape in ["flat", "wide", "deep", "hardlinked"] {
        let fixture = fixture_shape(shape);
        black_box(observe_fixture(fixture.path()));
        let mut elapsed_samples = Vec::with_capacity(30);
        let mut publication_samples = Vec::with_capacity(30);
        let mut context = (0, 0, 0);
        for _ in 0..30 {
            let (elapsed, publication, bytes, files, directories) = observe_fixture(fixture.path());
            elapsed_samples.push(elapsed);
            publication_samples.push(publication);
            context = (bytes, files, directories);
        }
        elapsed_samples.sort_unstable();
        publication_samples.sort_unstable();
        eprintln!(
            "fixture={shape} samples=30 warm total_p50={:.3}ms total_p95={:.3}ms publication_p50={:.3}ms publication_p95={:.3}ms serialized={}B files={} dirs={} engine_peak={}B",
            elapsed_samples[15].as_secs_f64() * 1000.0,
            elapsed_samples[28].as_secs_f64() * 1000.0,
            publication_samples[15].as_secs_f64() * 1000.0,
            publication_samples[28].as_secs_f64() * 1000.0,
            context.0, context.1, context.2, MemoryBudget::shared().peak()
        );
        group.bench_with_input(
            BenchmarkId::from_parameter(shape),
            &fixture,
            |benchmark, fixture| benchmark.iter(|| black_box(observe_fixture(fixture.path()))),
        );
    }
    group.finish();
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20)
.warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3));
targets = inventory_queries, scan_to_json, representative_shapes }
criterion_main!(benches);
