#pragma once

class VMT : public Address {
private:
	using saved_method_t = std::pair< size_t, Address >;

	Address                       m_orig_vmt;
	std::unique_ptr< Address[] >  m_clone;
	std::vector< saved_method_t > m_original_methods;

public:
	// c/dtor
	__forceinline  VMT( ) : Address{}, m_clone{}, m_original_methods{} {}
	__forceinline ~VMT( ) {
		unhook_all( );
	}

	__forceinline VMT( Address this_ptr,
					   bool    clone_table = false,
					   bool    preserve_rtti = false ) :
		Address( this_ptr ) {

		init( clone_table, preserve_rtti );
	}

	__forceinline void init( bool clone_table, bool preserve_rtti ) {
		uintptr_t clone;
		size_t    methods{};

		// get orig table vmt
		m_orig_vmt = *as< Address* >( );

		// if not cloning, we're done here.
		if ( !clone_table )
			return;

		// count methods in orig obj vmt
		count_methods( methods );

		// if preserving rtti, make space for one more ptr
		if ( preserve_rtti )
			methods += 1;

		// alloc space for a clone table and rtti ptr if we want
		m_clone = std::make_unique< Address[] >( methods );

		// make a cast cuz i dont want to keep casting this
		clone = ( uintptr_t )m_clone.get( );

		// copy over all methods
		util::copy(
			preserve_rtti ? clone + sizeof( Address ) : clone,
			m_orig_vmt,
			methods * sizeof( Address )
		);

		// check if we should preserve rtti and do a little hack to fix it
		if ( preserve_rtti )
			m_clone[ 0 ] = m_orig_vmt.as< Address* >( )[ -1 ];

		// then set the original objects vmt pointer to our cloned table
		set( preserve_rtti ? clone + sizeof( Address ) : clone );
	}

	__forceinline void count_methods( size_t& methods ) {
		while ( safe( m_orig_vmt.as< Address* >( )[ methods ] ) )
			methods++;
	}

	__forceinline void unhook_all( ) {
		for ( const auto& m : m_original_methods )
			to< Address* >( )[ std::get< size_t >( m ) ] = std::get< Address >( m );
	}

	__forceinline void unhook_method( size_t index ) {
		to< Address* >( )[ index ] = std::get< Address >( m_original_methods[ index ] );
	}

	__forceinline void hook_method( void* method, size_t index ) {
		hook_method( ( uintptr_t )method, index );
	}

	__forceinline void hook_method( Address hook_method, size_t index ) {
		m_original_methods.push_back( saved_method_t{ index, to< Address* >( )[ index ] } );
		to< Address* >( )[ index ] = hook_method;
	}

	template <typename t = Address>
	__forceinline t get_method( size_t index ) const {
		return m_orig_vmt.as< Address* >( )[ index ].as< t >( );
	}
};

namespace util {
	template <typename t = Address>
	__forceinline static t get_method( Address this_ptr, size_t index ) {
		return ( t )this_ptr.to< t* >( )[ index ];
	}
};