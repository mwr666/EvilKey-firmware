#include "ek_render_parallel.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static_assert(sizeof(EkRenderWorkerStats)==24, "diagnostic contract");
struct Pair {
    std::atomic<unsigned> entered{0}, completed{0}, overlapped{0};
    unsigned cores[2]={99,99};
    int outputs[2]={0,0};
    bool require_overlap=false;
};
struct Job {Pair *pair;unsigned index;};
static void job(void *arg) {
    auto *j=static_cast<Job *>(arg);Pair &p=*j->pair;
    p.cores[j->index]=ek_render_core_id();
    p.entered.fetch_or(1u<<j->index,std::memory_order_release);
    if(p.require_overlap) {
        auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(p.entered.load(std::memory_order_acquire)!=3 && std::chrono::steady_clock::now()<end)
            std::this_thread::yield();
        if(p.entered.load(std::memory_order_acquire)==3)p.overlapped.fetch_add(1);
    }
    p.outputs[j->index]=170+static_cast<int>(j->index);
    p.completed.fetch_add(1,std::memory_order_release);
}
static bool run_pair(bool overlap, bool expect_parallel) {
    Pair p;p.require_overlap=overlap;Job a{&p,0},b{&p,1};
    bool parallel=ek_render_parallel(job,&a,&b);
    assert(parallel==expect_parallel);
    assert(p.completed.load(std::memory_order_acquire)==2);
    assert(p.outputs[0]==170 && p.outputs[1]==171);
    if(overlap)assert(p.overlapped.load()==2);
    if(parallel) assert(p.cores[0]!=p.cores[1]);
    else assert(p.cores[0]==p.cores[1]);
    return parallel;
}
int main(int argc,char **argv) {
    bool serial=argc>1 && (std::strcmp(argv[1],"serial")==0 || std::strcmp(argv[1],"failure")==0);
    ek_render_worker_stats(nullptr);
    EkRenderWorkerStats stats{};ek_render_worker_stats(&stats);
    assert(!stats.ready && stats.enabled);
    run_pair(false,false); // before startup
    ek_render_workers_start();ek_render_workers_start();
    if(!serial && !ek_render_workers_ready()) {
        std::puts("FAIL: missing persistent concurrent worker pool");return 1;
    }
    if(serial) {
        assert(!ek_render_workers_ready());run_pair(false,false);
        ek_render_worker_stats(&stats);
        assert(!stats.ready && stats.jobs[0]==0 && stats.jobs[1]==0);
        std::puts(argc>1 && std::strcmp(argv[1],"failure")==0
                  ? "PASS: second-worker creation failure, cleanup, no partial publication, serial fallback"
                  : "PASS: no-backend fallback");return 0;
    }
    assert(run_pair(true,true)); // bounded rendezvous proves actual overlap
    ek_render_parallel_enable(false);run_pair(false,false);
    ek_render_worker_stats(&stats);assert(stats.ready && !stats.enabled);
    ek_render_parallel_enable(true);
    std::atomic<unsigned> parallel_count{0};
    std::vector<std::thread> callers;
    for(unsigned i=0;i<8;++i) callers.emplace_back([&] {
        for(unsigned n=0;n<80;++n) {
            Pair p;Job a{&p,0},b{&p,1};
            if(ek_render_parallel(job,&a,&b)) parallel_count.fetch_add(1);
            assert(p.completed.load()==2 && p.entered.load()==3);
            assert(p.outputs[0]==170 && p.outputs[1]==171);
        }
    });
    for(auto &t:callers)t.join();
    ek_render_worker_stats(&stats);
    assert(stats.jobs[0]>0 && stats.jobs[1]>0);
    assert(stats.jobs[0]+stats.jobs[1]==1+parallel_count.load());
    assert(!ek_render_parallel(nullptr,nullptr,nullptr));
    std::printf("PASS: overlap, join, opposite cores, 640 concurrent calls, disable fallback, jobs %u/%u\n",stats.jobs[0],stats.jobs[1]);
}
