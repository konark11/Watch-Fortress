# Imported RAG evaluation data

`cysekrag_corpus_derived.jsonl` is generated from the separately supplied
CysekRAG `eval_questions.jsonl` with `rag.import_cysekrag_eval`. It retains
the source corpus and row hashes but is not human-reviewed answer data.

Run development retrieval evaluation:

```powershell
python -m rag.evaluation experiments\data\rag\cysekrag_corpus_derived.jsonl `
  --split development --purpose development `
  --output experiments\results\cysekrag-development.json
```

Reserve `held_out_test` for one final fixed-configuration measurement. Review
a subset and add approved citations before running answer-mode citation scores.
