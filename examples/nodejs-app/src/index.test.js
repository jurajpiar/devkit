const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('Todo API', () => {
  it('should have a valid structure', () => {
    const todo = { id: 1, title: 'Test', completed: false };
    assert.strictEqual(typeof todo.id, 'number');
    assert.strictEqual(typeof todo.title, 'string');
    assert.strictEqual(typeof todo.completed, 'boolean');
  });

  it('should validate required fields', () => {
    const isValid = (todo) => todo.title && todo.title.length > 0;
    
    assert.strictEqual(isValid({ title: 'Valid' }), true);
    assert.strictEqual(isValid({ title: '' }), false);
    assert.strictEqual(isValid({}), false);
  });
});
