from app.connectors.elastic import build_elastic_query
from app.utils.checkpoint import ElasticCheckpoint


def test_query_builder_with_checkpoint() -> None:
    checkpoint = ElasticCheckpoint(last_ts="2024-05-01T10:11:12Z", last_id="xyz")
    query = build_elastic_query(
        checkpoint,
        max_events=500,
        start_ago_seconds=3600,
    )
    assert query["size"] == 500
    assert query["sort"] == [{"@timestamp": "asc"}, {"_id": "asc"}]
    filter_clause = query["query"]["bool"]["filter"][0]
    should = filter_clause["bool"]["should"]
    assert should[0] == {"range": {"@timestamp": {"gt": "2024-05-01T10:11:12Z"}}}
    assert should[1] == {
        "bool": {
            "must": [
                {"term": {"@timestamp": "2024-05-01T10:11:12Z"}},
                {"range": {"_id": {"gt": "xyz"}}},
            ]
        }
    }


def test_query_builder_without_checkpoint() -> None:
    checkpoint = ElasticCheckpoint()
    query = build_elastic_query(
        checkpoint,
        max_events=250,
        start_ago_seconds=900,
    )
    assert query["size"] == 250
    filter_clause = query["query"]["bool"]["filter"][0]
    assert filter_clause == {"range": {"@timestamp": {"gte": "now-900s"}}}
